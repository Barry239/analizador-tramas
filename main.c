#include <stdio.h>


void analizatrama(unsigned char []);
void analizaLLC(unsigned char []);


unsigned char uc[][6] = {"UI", "SIM", "-", "SARM", "UP", "-", "-", "SABM", "DISC", "-", "-", "SARME", "-", "-", "-", "SABME", "SNRM", "-", "-", "RSET", "-", "-", "-", "XID", "-", "-", "-", "SNRME"};
unsigned char ur[][5] = {"UI", "RIM", "-", "DM", "-", "-", "-", "-", "RD", "-", "-", "-", "UA", "-", "-", "-", "-", "FRMR", "-", "-", "-", "-", "-", "XID"};
unsigned char ss[][5] = {"RR", "RNR", "REJ", "SREJ"};


int main(int argc, char const *argv[]) {
    unsigned char t[][100] = {
        {0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x00, 0x02, 0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x03, 0xf0, 0xf0, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x05, 0x90, 0x6d},
        {0x00, 0x02, 0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x00, 0x03, 0xf0, 0xf1, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x90, 0x6d},
        {0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x00, 0x02, 0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x04, 0xf0, 0xf0, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xa3, 0x90, 0x6d},
        {0x00, 0x02, 0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x00, 0x04, 0xf0, 0xf1, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf2, 0x90, 0x6d},
        {0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x00, 0x02, 0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x12, 0xf0, 0xf0, 0x00, 0x01, 0x0e, 0x00, 0xff, 0xef, 0x19, 0x8f, 0xbc, 0x05, 0x7f, 0x00, 0x23, 0x00, 0x7f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x91, 0x6d},
        {0x00, 0x02, 0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x00, 0x12, 0xf0, 0xf0, 0x00, 0x03, 0x0e, 0x00, 0xff, 0xef, 0x17, 0x81, 0xbc, 0x05, 0x23, 0x00, 0x7f, 0x00, 0x23, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x91, 0x6d}
    };
    
    unsigned char i;
    for (i = 0; i < (sizeof(t) / sizeof(t[0])); i++) {
        printf("\n---------- Trama %2hhu ----------\n\n", i + 1);
        analizatrama(t[i]);
    }

    return 0;
}


void analizatrama(unsigned char t[]) {
    // Obtener tamaño/tipo
    unsigned short int tot = (t[12] << 8) | t[13];

    // Imprimir datos de la cabecera ethernet
    printf(".:: Cabecera Ethernet ::.\n\n");
    printf("MAC destino:\t%02X-%02X-%02X-%02X-%02X-%02X\n", t[0], t[1], t[2], t[3], t[4], t[5]);
    printf("MAC origen:\t%02X-%02X-%02X-%02X-%02X-%02X\n\n", t[6], t[7], t[8], t[9], t[10], t[11]);

    // Analizar según tamaño/tipo
    if (tot <= 1500) analizaLLC(t);
    else if (tot == 2048) printf("IP\n");
    else if (tot == 2054) printf("ARP\n");
    else printf(".:: Otro ::.\n\nTipo: 0x%02x 0x%02x\n", t[12], t[13]);
}

void analizaLLC(unsigned char t[]) {
    // Imprimir datos de la cabecera LLC
    printf(".:: Cabecera LLC ::.\n\n");

    // Analizar tipo de trama
    switch (t[16] & 3) {
        case 0:
        case 2:
            printf("T-I, N(s) = %d, N(r) = %d", t[16] >> 1, t[17] >> 1);
            if (t[17] & 1) printf(" - %c", (t[15] & 1 ? 'f' : 'p'));
            break;
        case 1:
            printf("T-S, S = %s, N(r) = %d", ss[(t[16] >> 2) & 3], t[17] >> 1);
            if (t[17] & 1) printf(" - %c", (t[15] & 1 ? 'f' : 'p'));
            break;
        case 3:
            printf("T-U");
            if (t[16] & 16) {
                if (t[15] & 1)
                    printf(", M = %s - f", ur[((t[16] >> 3) & 28) | ((t[16] >> 2) & 3)]);
                else
                    printf(", M = %s - p", uc[((t[16] >> 3) & 28) | ((t[16] >> 2) & 3)]);
            }
            break;
    }
    printf("\n");
}
