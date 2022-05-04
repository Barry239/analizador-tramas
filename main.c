#include <stdio.h>


#define MAX_ETH_HDR_SIZE 1518


void analizatrama(unsigned char []);
void analizaLLC(unsigned char []);
void analizaIP(unsigned char []);
void analizaARP(unsigned char []);


unsigned char uc[][6] = {"UI", "SIM", "-", "SARM", "UP", "-", "-", "SABM", "DISC", "-", "-", "SARME", "-", "-", "-", "SABME", "SNRM", "-", "-", "RSET", "-", "-", "-", "XID", "-", "-", "-", "SNRME"};
unsigned char ur[][5] = {"UI", "RIM", "-", "DM", "-", "-", "-", "-", "RD", "-", "-", "-", "UA", "-", "-", "-", "-", "FRMR", "-", "-", "-", "-", "-", "XID"};
unsigned char ss[][5] = {"RR", "RNR", "REJ", "SREJ"};


int main(int argc, char const *argv[]) {
    unsigned char t[][MAX_ETH_HDR_SIZE] = {
        {0x00, 0x14, 0xd1, 0xc2, 0x38, 0xbe, 0x00, 0x18, 0xe7, 0x33, 0x3d, 0xc3, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3c, 0x00, 0x32, 0x00, 0x00, 0x80, 0x01, 0xb5, 0x00, 0xc0, 0xa8, 0x02, 0x3c, 0xc0, 0xa8, 0x02, 0x02, 0x08, 0x00, 0x42, 0x5c, 0x02, 0x00, 0x09, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69},
        {0x00, 0x18, 0xe7, 0x33, 0x3d, 0xc3, 0x00, 0x14, 0xd1, 0xc2, 0x38, 0xbe, 0x08, 0x00, 0x47, 0x00, 0x00, 0x3c, 0x97, 0x00, 0x00, 0x00, 0x40, 0x01, 0x49, 0xcb, 0xc0, 0xa8, 0x02, 0x02, 0xc0, 0xa8, 0x02, 0x3c, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xab, 0xcd, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69}
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
    else if (tot == 2048) analizaIP(t);
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

void analizaIP(unsigned char t[]) {
    unsigned char ihl, i;

    // Imprimir datos de la cabecera IP
    printf(".:: Cabecera IP ::.\n\n");

    // Versión
    printf("Versi%cn:\t\t\t%d\n", 162, t[14] >> 4);

    // Longitud de cabecera de internet
    ihl = (t[14] & 15) * 4;
    printf("IHL:\t\t\t\t%d bytes\n", ihl);

    // Tipo de servicio
    printf("Tipo de servicio\n");
    printf("   Precedencia:\t\t\t");
    switch (t[15] >> 5) {
        case 0:
            printf("Routine\n");
            break;
        case 1:
            printf("Priority\n");
            break;
        case 2:
            printf("Immediate\n");
            break;
        case 3:
            printf("Flash\n");
            break;
        case 4:
            printf("Flash Override\n");
            break;
        case 5:
            printf("CRITIC/ECP\n");
            break;
        case 6:
            printf("Internetwork Control\n");
            break;
        case 7:
            printf("Network Control\n");
            break;
    }
    printf("   Retraso:\t\t\t%s\n", (t[15] & 16 ? "Bajo" : "Normal"));
    printf("   Rendimiento:\t\t\t%s\n", (t[15] & 16 ? "Alto" : "Normal"));
    printf("   Fiabilidad:\t\t\t%s\n", (t[15] & 16 ? "Alta" : "Normal"));
    printf("   Costo:\t\t\t%s\n", (t[15] & 16 ? "Bajo" : "Normal"));

    // Tamaño total
    printf("Tama%co total:\t\t\t%d bytes\n", 164, (t[16] << 8) | t[17]);

    // Identificador
    printf("Identificador:\t\t\t%d\n", 164, (t[18] << 8) | t[19]);

    // Banderas
    printf("Banderas:\n");
    printf("   Fragmentar:\t\t\t");
    t[20] & 64 ? printf("S%c\n", 161) : printf("No\n");
    printf("   %cltimo fragmento:\t\t", 233);
    t[20] & 32 ? printf("S%c\n", 161) : printf("No\n");

    // Desplazamiento de fragmento
    printf("Desplazamiento de fragmento:\t%d bytes\n", (((t[20] & 31) << 8) | t[21]) * 8);

    // Tiempo de vida
    printf("Tiempo de vida:\t\t\t%d saltos\n", t[22]);

    // Protocolo
    printf("Protocolo:\t\t\t");
    switch (t[23]) {
        case 1:
            printf("ICMP\n");
            break;
        case 2:
            printf("IGMP\n");
            break;
        case 6:
            printf("TCP\n");
            break;
        case 9:
            printf("IGRP\n");
            break;
        case 17:
            printf("UDP\n");
            break;
        case 47:
            printf("GRE\n");
            break;
        case 50:
            printf("ESP\n");
            break;
        case 51:
            printf("AH\n");
            break;
        case 57:
            printf("SKIP\n");
            break;
        case 88:
            printf("EIGRP\n");
            break;
        case 89:
            printf("OSPF\n");
            break;
        case 115:
            printf("L2TP\n");
            break;
        default:
            printf("Otro (0x%02x)\n", t[23]);
            break;
    }

    // Suma de control
    printf("Suma de control:\t\t0x%02x 0x%02x\n", t[24], t[25]);

    // IP origen
    printf("IP origen:\t\t\t%d.%d.%d.%d\n", t[26], t[27], t[28], t[29]);

    // IP destino
    printf("IP destino:\t\t\t%d.%d.%d.%d\n", t[30], t[31], t[32], t[33]);

    // Opciones
    printf("Opciones:%s", (ihl > 20 ? "\n" : "\t\t\tNinguna\n"));
    for (i = 34; i < ihl + 14; i +=4)
        printf("   0x%02x 0x%02x 0x%02x 0x%02x\n", t[i], t[i + 1], t[i + 2], t[i + 3]);
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
