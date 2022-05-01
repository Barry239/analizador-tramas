#include <stdio.h>


void analizatrama(unsigned char []);
void analizaLLC(unsigned char []);
void analizaARP(unsigned char []);


unsigned char uc[][6] = {"UI", "SIM", "-", "SARM", "UP", "-", "-", "SABM", "DISC", "-", "-", "SARME", "-", "-", "-", "SABME", "SNRM", "-", "-", "RSET", "-", "-", "-", "XID", "-", "-", "-", "SNRME"};
unsigned char ur[][5] = {"UI", "RIM", "-", "DM", "-", "-", "-", "-", "RD", "-", "-", "-", "UA", "-", "-", "-", "-", "FRMR", "-", "-", "-", "-", "-", "XID"};
unsigned char ss[][5] = {"RR", "RNR", "REJ", "SREJ"};


int main(int argc, char const *argv[]) {
    unsigned char t[][100] = {
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x01, 0x00, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0xfe, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
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
    else if (tot == 2054) analizaARP(t);
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

void analizaARP(unsigned char t[]) {
    // Imprimir datos de la cabecera ARP
    printf(".:: Cabecera ARP ::.\n\n");

    // Tipo de dirección de hardware
    printf("Tipo de direcci%cn de hardware:\t\t", 162);
    switch ((t[14] << 8) | t[15]) {
        case 1:
            printf("Ethernet\n");
            break;
        case 6:
            printf("IEEE 802 LAN\n");
            break;
        case 15:
            printf("Frame Relay\n");
            break;
        case 16:
            printf("ATM\n");
            break;
        default:
            printf("Otro (0x%02x 0x%02x)\n", t[14], t[15]);
            break;
    }

    // Tipo de dirección de protocolo
    printf("Tipo de direcci%cn de protocolo:\t\t", 162);
    if ((t[16] << 8) | t[17]) printf("IPv4\n");
    else printf("Otro (0x%02x 0x%02x)\n", t[16], t[17]);

    // Tamaño de dirección de hardware
    printf("Tama%co de direcci%cn de hardware:\t%d bytes\n", 164, 162, t[18]);

    // Tamaño de dirección de protocolo
    printf("Tama%co de direcci%cn de protocolo:\t%d bytes\n", 164, 162, t[19]);

    // Tipo de operación
    printf("Tipo de operaci%cn:\t\t\t", 162);
    switch ((t[20] << 8) | t[21]) {
        case 1:
            printf("Solicitud\n");
            break;
        case 2:
            printf("Respuesta\n");
            break;
        case 3:
            printf("Solicitud inversa\n");
            break;
        case 4:
            printf("Respuesta inversa\n");
            break;
        default:
            printf("Otro (0x%02x 0x%02x)\n", t[20], t[21]);
            break;
    }

    // Dirección de hardware origen
    printf("Direcci%cn de hardware origen:\t\t", 162);
    printf("%02X-%02X-%02X-%02X-%02X-%02X\n", t[22], t[23], t[24], t[25], t[26], t[27]);

    // Dirección de protocolo origen
    printf("Direcci%cn de protocolo origen:\t\t", 162);
    printf("%d.%d.%d.%d\n", t[28], t[29], t[30], t[31]);

    // Dirección de hardware destino
    printf("Direcci%cn de hardware destino:\t\t", 162);
    printf("%02X-%02X-%02X-%02X-%02X-%02X\n", t[32], t[33], t[34], t[35], t[36], t[37]);

    // Dirección de protocolo destino
    printf("Direcci%cn de protocolo destino:\t\t", 162);
    printf("%d.%d.%d.%d\n", t[38], t[39], t[40], t[41]);
}
