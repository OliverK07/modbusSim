#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>
#include <pthread.h>

#include "mbus.h"

struct mbus_tcp_func tcp_func = {
	.chk_dest = tcp_chk_pack_dest,
	.qry_parser = tcp_query_parser,
	.resp_parser = tcp_resp_parser,
	.build_qry = tcp_build_query,
	.build_excp = tcp_build_resp_excp,
	.build_0102_resp = tcp_build_resp_read_status,
	.build_0304_resp = tcp_build_resp_read_regs,
	.build_0506_resp = tcp_build_resp_set_single,
	.build_1516_resp = tcp_build_resp_multi,
};

void print_bin(int val2)
{
			for (int i = 7; i >= 0; i--)
			{
				if(val2 & (1 << i))
				printf("1");
				else
				printf("0");
			}
		printf(" ");

}

/*
 * Analyze modebus TCP query
 */
struct payload_reg {
	unsigned char byte;
	unsigned short *data;
};

struct payload_coil {
	unsigned char byte;
	unsigned char *data;
};


int tcp_query_parser(struct tcp_frm *rx_buf, struct thread_pack *tpack)
{
	unsigned short qtransID;
	unsigned short qmsglen;
	unsigned char qfc, rfc;
	unsigned short qstraddr, rstraddr;
	unsigned short qact, rlen;
	struct tcp_frm_para *tsfpara;
	struct tcp_tmp_frm *tmpara;

	tsfpara = tpack->tsfpara;
	tmpara = tpack->tmpara;

	qtransID = be16toh(rx_buf->transID);
	tsfpara->transID = qtransID;
	qmsglen = be16toh(rx_buf->msglen);
	qfc = rx_buf->fc;
	qstraddr = be16toh(rx_buf->straddr);
	qact = be16toh(rx_buf->act);

	rfc = qfc;
	rstraddr = qstraddr;
	rlen = tsfpara->len;

	tsfpara->len = rlen;
	tsfpara->fc = qfc;
	tsfpara->straddr = rstraddr;

/*  //our simulator don't care if fcs match!
	if(qfc != rfc){
		printf("<Modbus TCP Slave> Modbus TCP function code improper !!\n");
		return -1;
	}*/
	if(!(rfc ^ FORCESIGLEREGS)){                // FC = 0x05, get the status to write(on/off)
		pthread_mutex_lock(&(tpack->mutex));	
		tmpara->act = qact;		//lock !
		pthread_mutex_unlock(&(tpack->mutex));
		unsigned char tmp = SWAPU16(qact);
		if(tmp == 0xff){
			tpack->s_coil[qstraddr/8] |= 1 << (qstraddr%8);
		}else{
			tpack->s_coil[qstraddr/8] &= ~(1 << (qstraddr%8));
		}		
	}else if(!(rfc ^ PRESETEXCPSTATUS)){        // FC = 0x06, get the value to write
		if(qstraddr != rstraddr){
			printf("<Modbus TCP Slave> Query register address wrong (fc = 0x06)");
			printf(", query addr : %x | resp addr : %x\n", qstraddr, rstraddr);
			return -2;
		}
		pthread_mutex_lock(&(tpack->mutex));
		tmpara->act = qact;
		tpack->s_reg[qstraddr] = (int)SWAPU16(qact);
		pthread_mutex_unlock(&(tpack->mutex));
	}else if(!(rfc ^ FORCEMUILTCOILS)/*FC15*/){
		int byte_rem = 0;  			// byte remain
		int str_off = qstraddr%8;	// start offset, if 0 means start from head
		int qbit_value = 0;			// the value going to set
		struct payload_coil *pay = (struct payload_coil *)(rx_buf+1);
		unsigned char *tmp = (unsigned char*)malloc(qact/8 *sizeof(unsigned char));

		memcpy(tmp, rx_buf+1, pay->byte +1);
		tmpara->act = qact;
		for(int i=0;i<qact ;i++){
			qbit_value = tmp[1+ (i/8)] & (1 << i%8);
			if(qbit_value == 0){
				tpack->s_coil[qstraddr/8 + i/8 + (i+str_off)/8 ] &= ~(1 << (i+str_off)%8);
			}else{
				tpack->s_coil[qstraddr/8 + i/8 + (i+str_off)/8 ] |= (1 << (i+str_off)%8);
			}
		}
		pthread_mutex_lock(&(tpack->mutex));	
		tmpara->act = qact;
		pthread_mutex_unlock(&(tpack->mutex));
		free(tmp);
	}else if(!(rfc ^ PRESETMUILTREGS)/*FC16*/){
		struct payload_reg *pay = (struct payload_reg *)(rx_buf+1);
		unsigned char *tmp = (unsigned char*)malloc((qact*2+1) * sizeof(unsigned char));

		memcpy(tmp, rx_buf+1, pay->byte +1);
		for(int i=0;i< (pay->byte); i++){
			unsigned short val = tmp[1+(i+1)] << 8 | tmp[1+i];
			tpack->s_reg[qstraddr + i/2] = val; //store in LE
			i++;
		}
		pthread_mutex_lock(&(tpack->mutex));	
		tmpara->act = qact;
		pthread_mutex_unlock(&(tpack->mutex));
		free(tmp);
	}
	else{
		if((qstraddr + qact <= rstraddr + rlen) && (qstraddr >= rstraddr)){ // Query addr+shift len must smaller than the contain we set in addr+shift len
			pthread_mutex_lock(&(tpack->mutex));
			tmpara->straddr = qstraddr;
			tmpara->len = qact;
			pthread_mutex_unlock(&(tpack->mutex));
		}else{
			printf("<Modbus TCP Slave> The address have no contain\n");
			printf("Query addr : %x, shift len : %x | Respond addr: %x, shift len : %x\n",
					 qstraddr, qact, rstraddr, rlen);
			return -2;
		}
	}
	return 0;
}
/* 
 * Check query Portocol ID/Unit ID correct or not. 
 * If wrong, return -1 then throw away it !
 */
 	//
	//TODO: change this in DEBUG_MODE
	//
int tcp_chk_pack_dest(struct tcp_frm *rx_buf, struct tcp_frm_para *tfpara)
{
	unsigned short qpotoID;
	unsigned char qunitID, runitID;

	qpotoID = be16toh(rx_buf->potoID);
	qunitID = rx_buf->unitID;
	runitID = qunitID;

	if(qpotoID != (unsigned short)TCPMBUSPROTOCOL){
		printf("<Modbus TCP> recv query protocol ID wrong !!\n");
		return -1;
	}
	if(qunitID != runitID){
		printf("<Modbus TCP> the destination of recv query wrong !!(unit ID) : ");
		printf("Query unitID : %x | Respond unitID : %x\n", qunitID, runitID);
		return -1;
	}

	return 0;
}
/*
 * Analyze modbus TCP respond
 */
int tcp_resp_parser(unsigned char *rx_buf, struct tcp_frm_para *tmfpara, int rlen)
{
	int i;
	int act_byte;
	unsigned short tmp16;
	unsigned char qfc, rfc;
	unsigned short qact, ract;
	unsigned short qlen;
	unsigned short raddr;
	unsigned short rrlen;
	char *s[EXCPMSGTOTAL] = {"<Modbus TCP Master> Read Coil Status (FC=01) exception !!",
							 "<Modbus TCP Master> Read Input Status (FC=02) exception !!",
							 "<Modbus TCP Master> Read Holding Registers (FC=03) exception !!",
							 "<Modbus TCP Master> Read Input Registers (FC=04) exception !!",
							 "<Modbus TCP Master> Force Single Coil (FC=05) exception !!",
							 "<Modbus TCP Master> Preset Single Register (FC=06) exception !!"
							};
	
	qfc = tmfpara->fc;
	rfc = *(rx_buf+7);
	qlen = tmfpara->len;
	rrlen = *(rx_buf+8);
	
	if(qfc != rfc){
		if(rfc > PRESETEXCPSTATUS_EXCP || rfc < READCOILSTATUS_EXCP){
			printf("<Modbus TCP Master> unknown respond function code : %x !!\n", rfc);
			return -1;
		}	
		printf("%s\n", s[rfc - READCOILSTATUS_EXCP]);	
		return -1;
	}
	
	if(!(rfc ^ READCOILSTATUS) || !(rfc ^ READINPUTSTATUS)){		// fc = 0x01/0x02, detect data len
		act_byte = carry((int)qlen, 8);

		if(rrlen != act_byte){
			printf("<Modbus TCP Master> recv respond length wrong (rlen = %d | qlen = %d)\n", rrlen, act_byte);
			return -1;
		}
		printf("<Modbus TCP Master> Data : ");
		for(i = 9; i < rlen; i++){
			printf(" %x |", *(rx_buf+i));
		}
		printf("\n");
	}else if(!(rfc ^ READHOLDINGREGS) || !(rfc ^ READINPUTREGS)){	// fc = 0x03/0x04, detect data byte
		if(rrlen != qlen << 1){
			printf("<Modbus TCP Master> recv respond byte wrong !!\n");
			return -1;
		}
		printf("<Modbus TCP Master> Data : ");
		for(i = 9; i < rlen; i+=2){
			printf(" %x%x |", *(rx_buf+i), *(rx_buf+i+1));
		}
		printf("\n");
	}else if(!(rfc ^ FORCESIGLEREGS)){								// fc = 0x05, get write on/off status
		memcpy(&tmp16, rx_buf+8, sizeof(tmp16));
		raddr = ntohs(tmp16);
		ract = *(rx_buf+10);
		if(ract == 255){
			printf("<Modbus TCP Master> addr : %x The status to wirte on (FC:0x05)\n", raddr);
		}else if(!ract){
			printf("<Modbus TCP Master> addr : %x The status to wirte off (FC:0x05)\n", raddr);
		}else{
			printf("<Modbus TCP Master> Unknown status (FC:0x04)\n");
			return -1;
		}
	}else if(!(rfc ^ PRESETEXCPSTATUS)){							// fc = 0x06, get status on register
		qact = tmfpara->act;
		memcpy(&tmp16, rx_buf+8, sizeof(tmp16));
		raddr = ntohs(tmp16);
		memcpy(&tmp16, rx_buf+10, sizeof(tmp16));
		ract = ntohs(tmp16);
		if(qact != ract){
			printf("<Modbus TCP Master> Action fail (FC:0x06) ");
			printf("Query action : %x | Respond action : %x\n", qact, ract);
			return -1;
		}
		printf("<Modbus TCP Master> addr : %x Action code : %x\n", raddr, ract);
	}else{															// fc = Unknown 
		printf("<Modbus TCP Master> Unknown Function code %x !!\n", rfc);
		return -1;
	}
	
	return 0;
}
/*
 * build Modbus TCP query
 */			
int tcp_build_query(struct tcp_frm *tx_buf, struct tcp_frm_para *tmfpara)
{
	tx_buf->transID = htons(tmfpara->transID);
	tx_buf->potoID = htons(tmfpara->potoID);
	tx_buf->msglen = htons((unsigned short)TCPQUERYMSGLEN);
	tx_buf->unitID = tmfpara->unitID;
	tx_buf->fc = tmfpara->fc;
	tx_buf->straddr = htons(tmfpara->straddr);
	if(tmfpara->fc == 5 || tmfpara->fc == 6){
		tx_buf->act = htons(tmfpara->act);
	}else{
		tx_buf->act = htons(tmfpara->len);
	}

	return 0;
}
/*
 * build modbus TCP respond exception
 */
int tcp_build_resp_excp(struct tcp_frm_excp *tx_buf, struct tcp_frm_para *tsfpara, unsigned char excp_code)
{
	int txlen;
	unsigned short msglen;
	unsigned char excpfc;	

	msglen = (unsigned short)TCPRESPEXCPMSGLEN;

	tx_buf->transID = htons(tsfpara->transID);
	tx_buf->potoID = htons(tsfpara->potoID);
	tx_buf->msglen = htons(msglen);
	tx_buf->unitID = tsfpara->unitID;
	excpfc = tsfpara->fc | EXCPTIONCODE;
	tx_buf->fc = excpfc;	
    tx_buf->ec = excp_code;	

	txlen = TCPRESPEXCPFRMLEN; 

	printf("<Modbus TCP Slave> respond Excption Code");
        
	return txlen;
}
/*
 * FC 0x01 Read Coil Status respond / FC 0x02 Read Input Status
 */
int tcp_build_resp_read_status(struct tcp_frm_rsp *tx_buf, struct thread_pack *tpack, unsigned char fc)
{
	int byte;
	int txlen;
	unsigned short msglen;
	unsigned short len;   
	int straddr;

	len = tpack->tmpara->len;
	byte = carry((int)len, 8);
	txlen = byte + 9;
	msglen = byte + 3;	
	tpack->tsfpara->msglen = msglen;
	tx_buf->transID = htons(tpack->tsfpara->transID);
	tx_buf->potoID = htons(tpack->tsfpara->potoID);
	tx_buf->msglen = htons(tpack->tsfpara->msglen);
	tx_buf->unitID = tpack->tsfpara->unitID;
	tx_buf->fc = fc;
	tx_buf->byte = (unsigned char)byte;
	
	straddr = tpack->tsfpara->straddr;		// start address

	int shift = len %8;						//shift how many 
	int arr_str = straddr%8;				// if ==0 ,means from head
	int hd_str = straddr/8; 				// array head addr
	unsigned char *tmp = (unsigned char*) malloc(byte*sizeof(unsigned char));
	unsigned char *c_tmp = (unsigned char*)malloc(sizeof(unsigned char));//rest packet

	if(arr_str == 0){
		if(shift == 0){
			memcpy(tmp, tpack->s_coil+ straddr/8, byte);
		}else{

			if(byte > 1)
				memcpy(tmp, tpack->s_coil+ straddr/8, byte-1);
			//build rest packet.
			*c_tmp = (*(tpack->s_coil+ (straddr/8) + byte-1 )) & (0xff>>(8-shift));
			memcpy(tmp+byte-1, c_tmp, 1);
		}
	}else{
		if(shift == 0){ 					//request complete byte
			for(int i=0;i<byte;i++){
				*c_tmp = ((*(tpack->s_coil+ hd_str + i )) & (0xff << shift))>> shift 
						| ((*(tpack->s_coil+ hd_str + i +1)) & (0xff >> shift))<< shift;
				memcpy(tmp+i, c_tmp,1);
			}
		}else{
			for(int i=0;i<byte-1;i++){
				*c_tmp = ((*(tpack->s_coil+ hd_str + i )) & (0xff << shift))>> shift 
						| ((*(tpack->s_coil+ hd_str + i +1)) & (0xff >> shift))<< shift;
				memcpy(tmp+i, c_tmp,1);
			}
			//last byte
				*c_tmp = ((*(tpack->s_coil+ hd_str + byte )) & (0xff >> shift));
				memcpy(tmp+byte-1, c_tmp, 1);

		}
	}
	memcpy(tx_buf+1, tmp, byte);
	free(tmp);
	free(c_tmp);
	return txlen;
}
/*
 * FC 0x03 Read Holding Registers respond / FC 0x04 Read Input Registers respond
 */ 
int tcp_build_resp_read_regs(struct tcp_frm_rsp *tx_buf, struct thread_pack *tpack, unsigned char fc)
{
	int byte;
	int txlen;
	unsigned int num_regs;
	unsigned short msglen;

	num_regs = tpack->tmpara->len;
	byte = num_regs * 2;
	txlen = byte + 9;
	msglen = byte + 3;  
	tpack->tsfpara->msglen = msglen;

	tx_buf->transID = htons(tpack->tsfpara->transID);
	tx_buf->potoID = htons(tpack->tsfpara->potoID);
	tx_buf->msglen = htons(tpack->tsfpara->msglen);
	tx_buf->unitID = tpack->tsfpara->unitID;
	tx_buf->fc = fc;
	tx_buf->byte = (unsigned char)byte;

	memcpy(tx_buf+1, tpack->s_reg + tpack->tsfpara->straddr, byte);
	return txlen;
}
/* 
 * FC 0x05 Force Single Coli respond / FC 0x06 Preset Single Register respond
 */ 
int tcp_build_resp_set_single(struct tcp_frm *tx_buf, struct thread_pack *tpack, unsigned char fc)
{
	int txlen;

	tpack->tsfpara->msglen = (unsigned short)TCPRESPSETSIGNALLEN;	
	txlen = TCPRESPSETSIGNALLEN + 6;

	tx_buf->transID = htons(tpack->tsfpara->transID);
	tx_buf->potoID = htons(tpack->tsfpara->potoID);
	tx_buf->msglen = htons(tpack->tsfpara->msglen);
	tx_buf->unitID = tpack->tsfpara->unitID;
	tx_buf->fc = fc;
	tx_buf->straddr = htons(tpack->tsfpara->straddr);
	tx_buf->act = htons(tpack->tmpara->act);

	return txlen;
}
/*
 * FC 0x0f, force multiple coil / FC 0x0A preset multiple registers
 */
int tcp_build_resp_multi(struct tcp_frm *tx_buf, struct thread_pack *tpack, unsigned char fc)
{
	int txlen;
	tpack->tsfpara->msglen = (unsigned short)TCPRESPSETSIGNALLEN;
	txlen = TCPRESPSETSIGNALLEN + 6;

	tx_buf->transID = htons(tpack->tsfpara->transID);
	tx_buf->potoID = htons(tpack->tsfpara->potoID);
	tx_buf->msglen = htons(tpack->tsfpara->msglen);
	tx_buf->unitID = tpack->tsfpara->unitID;
	tx_buf->fc = fc;
	tx_buf->straddr = htons(tpack->tsfpara->straddr);
	tx_buf->act = htons(tpack->tmpara->act);

	return txlen;
}