#include <stdio.h>


#define MAX_ETH_HDR_SIZE 1518


void analizatrama(unsigned char []);
void analizaLLC(unsigned char []);
void analizaIP(unsigned char []);
void analizaARP(unsigned char []);
void analizaICMP(unsigned char [], unsigned char, unsigned char);
void analizaTCP(unsigned char [], unsigned char);
void analizaUDP(unsigned char [], unsigned char);
void checksum(unsigned char [], unsigned char);


unsigned char uc[][6] = {"UI", "SIM", "-", "SARM", "UP", "-", "-", "SABM", "DISC", "-", "-", "SARME", "-", "-", "-", "SABME", "SNRM", "-", "-", "RSET", "-", "-", "-", "XID", "-", "-", "-", "SNRME"};
unsigned char ur[][5] = {"UI", "RIM", "-", "DM", "-", "-", "-", "-", "RD", "-", "-", "-", "UA", "-", "-", "-", "-", "FRMR", "-", "-", "-", "-", "-", "XID"};
unsigned char ss[][5] = {"RR", "RNR", "REJ", "SREJ"};


int main(int argc, char const *argv[]) {
    unsigned char t[][MAX_ETH_HDR_SIZE] = {
        // {0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x1c, 0xc0, 0x7b, 0x35, 0xa1, 0x08, 0x00, 0x48, 0x00, 0x00, 0x48, 0x5c, 0x7d, 0x00, 0x00, 0x80, 0x01, 0x6c, 0x88, 0x94, 0xcc, 0x39, 0xc3, 0x94, 0xcc, 0x00, 0x49, 0x07, 0x0b, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x3b, 0x5c, 0x02, 0x00, 0x10, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69}, // ICMP
        // {0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3c, 0x01, 0xb5, 0x00, 0x00, 0x3f, 0x01, 0xdb, 0xc7, 0x94, 0xcc, 0x3a, 0xe1, 0x94, 0xcc, 0x39, 0xcb, 0x00, 0x00, 0x51, 0x5c, 0x03, 0x00, 0x01, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69}, // ICMP
        // {0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3c, 0x04, 0x57, 0x00, 0x00, 0x80, 0x01, 0x98, 0x25, 0x94, 0xcc, 0x39, 0xcb, 0x94, 0xcc, 0x3a, 0xe1, 0x08, 0x00, 0x49, 0x5c, 0x03, 0x00, 0x01, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69} // ICMP
        {0x02, 0xff, 0x53, 0xc3, 0xe9, 0xab, 0x00, 0xff, 0x66, 0x7f, 0xd4, 0x3c, 0x08, 0x00, 0x45, 0x00, 0x00, 0x30, 0x2c, 0x00, 0x40, 0x00, 0x80, 0x06, 0x4b, 0x74, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01, 0x04, 0x03, 0x00, 0x15, 0x00, 0x3b, 0xcf, 0x44, 0x00, 0x00, 0x00, 0x00, 0x50, 0x20, 0x20, 0x00, 0x0c, 0x34, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02}, // TCP
        {0x00, 0xff, 0x66, 0x7f, 0xd4, 0x3c, 0x02, 0xff, 0x53, 0xc3, 0xe9, 0xab, 0x08, 0x00, 0x45, 0x00, 0x00, 0x30, 0x05, 0xc4, 0x40, 0x00, 0x80, 0x06, 0x71, 0xb0, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, 0x00, 0x15, 0x04, 0x03, 0x21, 0x5d, 0x3a, 0x44, 0x00, 0x3b, 0xcf, 0x45, 0x70, 0x12, 0x44, 0x70, 0x8c, 0x11, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02}, // TCP
        {0x00, 0x01, 0xf4, 0x43, 0xc9, 0x19, 0x00, 0x18, 0xe7, 0x33, 0x3d, 0xc3, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0xf6, 0x18, 0x40, 0x00, 0x80, 0x06, 0x6b, 0xa4, 0x94, 0xcc, 0x19, 0xf5, 0x40, 0xe9, 0xa9, 0x68, 0x08, 0x3a, 0x00, 0x50, 0x42, 0xfe, 0xd8, 0x4a, 0x6a, 0x66, 0xac, 0xc8, 0x50, 0x10, 0x42, 0x0e, 0x00, 0x00, 0x00, 0x00} // TCP
        // {0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x08, 0x00, 0x46, 0x00, 0x80, 0x42, 0x04, 0x55, 0x34, 0x11, 0x80, 0x11, 0x6b, 0xf0, 0x94, 0xcc, 0x39, 0xcb, 0x94, 0xcc, 0x67, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x04, 0x0c, 0x00, 0x35, 0x00, 0x2e, 0x85, 0x7c, 0xe2, 0x1a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x03, 0x69, 0x73, 0x63, 0x05, 0x65, 0x73, 0x63, 0x6f, 0x6d, 0x03, 0x69, 0x70, 0x6e, 0x02, 0x6d, 0x78, 0x00, 0x00, 0x1c, 0x00, 0x01}, // UDP
        // {0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x08, 0x00, 0x45, 0x00, 0x00, 0x6f, 0x90, 0x30, 0x40, 0x00, 0xfb, 0x11, 0x24, 0xe7, 0x94, 0xcc, 0x67, 0x02, 0x94, 0xcc, 0x39, 0xcb, 0x00, 0x35, 0x04, 0x0c, 0x00, 0x5b, 0xe8, 0x60, 0xe2, 0x1a, 0x85, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x03, 0x69, 0x73, 0x63, 0x05, 0x65, 0x73, 0x63, 0x6f, 0x6d, 0x03, 0x69, 0x70, 0x6e, 0x02, 0x6d, 0x78, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x14, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x21, 0x04, 0x64, 0x6e, 0x73, 0x31, 0xc0, 0x1a, 0x03, 0x74, 0x69, 0x63, 0xc0, 0x1a, 0x77, 0xec, 0xdf, 0x29, 0x00, 0x00, 0x2a, 0x30, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x2a, 0x30}, // UDP
        // {0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x08, 0x00, 0x45, 0x00, 0x00, 0x42, 0x04, 0x56, 0x00, 0x00, 0x80, 0x11, 0x6b, 0xef, 0x94, 0xcc, 0x39, 0xcb, 0x94, 0xcc, 0x67, 0x02, 0x04, 0x0c, 0x00, 0x35, 0x00, 0x2e, 0xff, 0x87, 0x68, 0x2a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x03, 0x69, 0x73, 0x63, 0x05, 0x65, 0x73, 0x63, 0x6f, 0x6d, 0x03, 0x69, 0x70, 0x6e, 0x02, 0x6d, 0x78, 0x00, 0x00, 0x01, 0x00, 0x01} // UDP
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
    printf("Tipo de servicio:\n");
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
    if (t[20] & 64) printf("S%c\n", 161);
    else printf("No\n");
    printf("   %cltimo fragmento:\t\t", 233);
    if (t[20] & 32) printf("S%c\n", 161);
    else printf("No\n");

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
    printf("Suma de control:\t\t0x%02x 0x%02x ", t[24], t[25]);
    checksum(t, ihl);

    // IP origen
    printf("IP origen:\t\t\t%d.%d.%d.%d\n", t[26], t[27], t[28], t[29]);

    // IP destino
    printf("IP destino:\t\t\t%d.%d.%d.%d\n", t[30], t[31], t[32], t[33]);

    // Opciones
    printf("Opciones:%s", (ihl > 20 ? "\n" : "\t\t\tNinguna\n"));
    for (i = 34; i < ihl + 14; i += 4)
        printf("   0x%02x 0x%02x 0x%02x 0x%02x\n", t[i], t[i + 1], t[i + 2], t[i + 3]);

    // Analizar según protocolo
    switch (t[23]) {
        case 1:
            analizaICMP(t, ihl, (t[16] << 8) | t[17]);
            break;
        case 6:
            analizaTCP(t, ihl);
            break;
        case 17:
            analizaUDP(t, ihl);
            break;
    }
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

void analizaICMP(unsigned char t[], unsigned char ihl, unsigned char tt) {
    unsigned char i;

    // Imprimir datos de la cabecera ICMP
    printf("\n.:: Cabecera ICMP ::.\n\n");

    // Tipo
    printf("Tipo:\t\t\t");
    switch (t[ihl + 14]) {
        case 0:
            printf("Respuesta de ECO\n");
            break;
        case 3:
            printf("Destino inalcanzable\n");
            break;
        case 4:
            printf("Fuente saciable\n");
            break;
        case 5:
            printf("Redirecci%cn\n", 162);
            break;
        case 8:
            printf("Solicitud de ECO\n");
            break;
        case 11:
            printf("Tiempo excedido\n");
            break;
        case 12:
            printf("Problema de par%cmetros\n", 160);
            break;
        case 13:
            printf("Timestamp\n");
            break;
        case 14:
            printf("Respuesta de timestamp\n");
            break;
        case 15:
            printf("Solicitud de informaci%cn\n", 162);
            break;
        case 16:
            printf("Respuesta de informaci%cn\n", 162);
            break;
        default:
            printf("Otro (0x%02x)\n", t[ihl + 14]);
            break;
    }

    // Código
    printf("C%cdigo:\t\t\t%d\n", 162, t[ihl + 15]);

    // Suma de control
    printf("Suma de control:\t0x%02x 0x%02x\n", t[ihl + 16], t[ihl + 17]);

    // Datos
    printf("Datos:%s", (tt - ihl > 4 ? "\n" : "\t\t\tNinguno\n"));
    for (i = ihl + 18; i < tt + 14; i++)
        printf("%s 0x%02x%s", (i - ihl - 22) % 4 ? "" : "  ", t[i], (i - ihl - 21) % 4 ? "" : "\n");
    if ((tt - ihl) % 4) printf("\n");
}

void analizaTCP(unsigned char t[], unsigned char ihl) {
    unsigned char offset, i;

    // Imprimir datos de la cabecera TCP
    printf("\n.:: Cabecera TCP ::.\n\n");

    // Puerto de origen
    printf("Puerto de origen:\t\t%d\n", (t[ihl + 14] << 8) | t[ihl + 15]);

    // Puerto de destino
    printf("Puerto de destino:\t\t%d\n", (t[ihl + 16] << 8) | t[ihl + 17]);

    // Número de secuencia
    printf("N%cmero de secuencia:\t\t%d\n", 163, (t[ihl + 18] << 24) | (t[ihl + 19] << 16) | (t[ihl + 20] << 8) | t[ihl + 21]);

    // Número de reconocimiento
    printf("N%cmero de reconocimiento:\t%d\n", 163, (t[ihl + 22] << 24) | (t[ihl + 23] << 16) | (t[ihl + 24] << 8) | t[ihl + 25]);

    // Desplazamiento de datos
    offset = (t[ihl + 26] >> 4) * 4;
    printf("Desplazamiento de datos:\t%d bytes\n", offset);

    // Bits de control
    printf("Bits de control:\n", 162);
    printf("   CWR:\t\t\t\t%c\n", t[ihl + 27] & 128 ? '1' : '0');
    printf("   ECE:\t\t\t\t%c\n", t[ihl + 27] & 64 ? '1' : '0');
    printf("   URG:\t\t\t\t%c\n", t[ihl + 27] & 32 ? '1' : '0');
    printf("   ACK:\t\t\t\t%c\n", t[ihl + 27] & 16 ? '1' : '0');
    printf("   PSH:\t\t\t\t%c\n", t[ihl + 27] & 8 ? '1' : '0');
    printf("   RST:\t\t\t\t%c\n", t[ihl + 27] & 4 ? '1' : '0');
    printf("   SYN:\t\t\t\t%c\n", t[ihl + 27] & 2 ? '1' : '0');
    printf("   FIN:\t\t\t\t%c\n", t[ihl + 27] & 1 ? '1' : '0');
    
    // Ventana
    printf("Ventana:\t\t\t%d\n", (t[ihl + 28] << 8) | t[ihl + 29]);

    // Suma de control
    printf("Suma de control:\t\t0x%02x 0x%02x\n", t[ihl + 30], t[ihl + 31]);

    // Puntero urgente
    printf("Puntero urgente:\t\t%d bytes\n", t[ihl + 32], t[ihl + 33]);

    // Opciones
    printf("Opciones:%s", (offset > 20 ? "\n" : "\t\t\tNinguna\n"));
    for (i = ihl + 34; i < offset + ihl + 14; i += 4)
        printf("   0x%02x 0x%02x 0x%02x 0x%02x\n", t[i], t[i + 1], t[i + 2], t[i + 3]);
}

void analizaUDP(unsigned char t[], unsigned char ihl) {
    unsigned char length, i;

    // Imprimir datos de la cabecera UDP
    printf("\n.:: Cabecera UDP ::.\n\n");

    // Puerto de origen
    printf("Puerto de origen:\t\t%d\n", (t[ihl + 14] << 8) | t[ihl + 15]);

    // Puerto de destino
    printf("Puerto de destino:\t\t%d\n", (t[ihl + 16] << 8) | t[ihl + 17]);

    // Longitud
    length = (t[ihl + 18] << 8) | t[ihl + 19];
    printf("Longitud:\t\t\t%d bytes\n", length);

    // Suma de control
    printf("Suma de control:\t\t0x%02x 0x%02x\n", t[ihl + 20], t[ihl + 21]);

    // Datos
    printf("Datos:%s", (length > 8 ? "\n" : "\t\t\t\tNinguno\n"));
    for (i = ihl + 22; i < length + ihl + 14; i++)
        printf("%s 0x%02x%s", (i - ihl - 22) % 4 ? "" : "  ", t[i], (i - ihl - 21) % 4 ? "" : "\n");
    if (length % 4) printf("\n");
}

void checksum(unsigned char t[], unsigned char tam) {
    unsigned char i;
    unsigned int cs = 0;

    for (i = 14; i < tam + 14; i += 2) cs += (t[i] << 8) | t[i + 1];

    cs += cs >> 16;
    cs = ~cs & 0xffff;

    if (!cs) printf("(Correcto)\n");
    else printf("(Incorrecto, 0x%02x 0x%02x)\n", cs >> 8, cs & 0xff);
}
