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
	tsfpara->fc = qfc;
	rstraddr = qstraddr;
	tsfpara->straddr = rstraddr;
	rlen = tsfpara->len;//keep this just for now
	tsfpara->len = rlen;

	if(qmsglen != TCPQUERYMSGLEN){
		printf("<Modbus TCP Slave> Modbus TCP message length should be 6 byte !!\n");
		return -4;
	}

	if(qfc != rfc){
		printf("<Modbus TCP Slave> Modbus TCP function code improper !!\n");
		return -1;
	}

	if(!(rfc ^ FORCESIGLEREGS)){                // FC = 0x05, get the status to write(on/off)
		//if(!qact || qact == 0xff<<8)
		{	//on
			pthread_mutex_lock(&(tpack->mutex));	
			tmpara->act = qact;		//lock !
			printf("before swap:%04x\n",qact);
			unsigned char tmp = SWAPU16(qact);
			if(tmp == 0xff){ //set on
				tpack->s_coil[qstraddr/8] |= 1 << (qstraddr%8);
			}else{
				tpack->s_coil[qstraddr/8] &= ~(1 << (qstraddr%8));
			}
			printf("after swap:%04x\n",tmp);
			printf("***    set bit_addr[%d]:%04x    ***\n", qstraddr/8,tpack->s_coil[qstraddr/8] );
			pthread_mutex_unlock(&(tpack->mutex));
		}
		
		/*else{
			printf("<Modbus TCP Slave> Query set the status to write  worng(fc = 0x05)\n");
			return -3;
		}
		if(qstraddr != rstraddr){
			printf("<Modbus TCP Slave> Query register address wrong (fc = 0x05)");
			printf(", query addr : %x | resp addr : %x\n", qstraddr, rstraddr);
			return -2;
		}*/
		
	}else if(!(rfc ^ PRESETEXCPSTATUS)){        // FC = 0x06, get the value to write
		if(qstraddr != rstraddr){
			printf("<Modbus TCP Slave> Query register address wrong (fc = 0x06)");
			printf(", query addr : %x | resp addr : %x\n", qstraddr, rstraddr);
			return -2;
		}
		pthread_mutex_lock(&(tpack->mutex));
		tmpara->act = qact;
		tpack->s_reg[qstraddr] = (int)SWAPU16(qact);
		printf("***    set Register[%d]:%d    ***\n", qstraddr, qact);
		pthread_mutex_unlock(&(tpack->mutex));
	}else if(!(rfc ^ FORCEMUILTCOILS)/*FC15*/){
		//qact for  how many coils, qstraddr for start address, following data will be "X BYTE" "DATA" "DATA"
		
		struct payload_coil *pay = (struct payload_coil *)(rx_buf+1);
		printf("write multi register byte: %x\n", pay->byte);
/*		for(int i=0;i< (pay->byte - '0'); i+=2){
			tpack->s_coil[qstraddr + i] = SWAPU16((pay->data) ); //store in LE
		}
*/
		//qact as how many bits
		for(int i=0;i<qact ;i++){
			int carry_over = (qstraddr%8 +i)/8;
			if(((*(pay->data + i/8) - '0') & 1<<(i%8)) == 1){
				tpack->s_coil[qstraddr/8 + carry_over] |= 1 << (i+qstraddr)%8;
				// |= the value
			}else{
				tpack->s_coil[qstraddr/8 + carry_over] &= ~(1 << (i+qstraddr)%8);
				// &= ~()
			}
		}
/*
		for(int i=0;i< (pay->byte - '0'); i++){
			//firstbyte 
			for(int j=0;j<8;j++){
				if(SWAPU16((pay->data + i)) & (1<<i)){
					tpack->s_coil[qstraddr/8]
				}else{

				}
			}
		}
*/		

	}else if(!(rfc ^ PRESETMUILTREGS)/*FC16*/){
		//memcpy(dst, src, count)
		//
		// TODO: check if this is correct.
		//
		struct payload_reg *pay = (struct payload_reg *)(rx_buf+1);
		printf("write multi register byte: %x\n", pay->byte);
		for(int i=0;i< (pay->byte - '0'); i++){
			unsigned short val = *(pay->data +i);
			tpack->s_reg[qstraddr + i] = SWAPU16(val); //store in LE
		}
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
int tcp_chk_pack_dest(struct tcp_frm *rx_buf, struct tcp_frm_para *tfpara)
{
	unsigned short qpotoID;
	unsigned char qunitID, runitID;

	qpotoID = be16toh(rx_buf->potoID);
	qunitID = rx_buf->unitID;
	//make response ID is request unitID
	//
	//TODO: change this in DEBUG_MODE
	//

	//runitID = tfpara->unitID;
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

	//memset(tx_buf+1, 9, byte);		// tx_buf+1 shift a size of sturct "tcp_frm_rsp" (9 byte)
	memcpy(tx_buf+1, tpack->s_coil + tpack->tsfpara->straddr, byte);

	printf("<Modbus TCP Slave> respond Read %s Status\n", fc==READCOILSTATUS?"Coil":"Input");

	printf("printf s_coil data:\n");
	for(int i=0;i < 20;i++) printf("|%08x ",tpack->s_coil[i]);
	printf("\n================\n");
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
		
	//memset(tx_buf+1, 1, byte);		// tx_buf+1 shift a size of struct "tcp_frm_rsp" (9 byte)
	printf("%s,memcpy bytes:%d, read addr:%d\n",__FUNCTION__,byte, tpack->tsfpara->straddr);
	memcpy(tx_buf+1, tpack->s_reg + tpack->tsfpara->straddr, byte);
	
	printf("<Modbus TCP Slave> respond Read %s Registers\n", fc==READHOLDINGREGS?"Holding":"Input");
	
	printf("printf s_reg data:\n");
	for(int i=0;i < 20;i++) printf("%d ",tpack->s_reg[i]);
	printf("\n================\n");

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

	printf("<Modbus TCP Slave> respond %s\n", fc==FORCESIGLEREGS?"Force Single Coli":"Preset Single Register");

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

	printf("<Modbus TCP Slave> respond %s\n", fc==FORCEMUILTCOILS?" FC15 FORCEMUILTCOILS":"FC16 PRESETMUILTREGS");

	return txlen;
}




