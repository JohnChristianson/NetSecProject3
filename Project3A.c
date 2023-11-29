#include <stdio.h>
#include <stdlib.h>
#include "SDES.h"
#include <stdbool.h>
#include <time.h>
#include <string.h>

// A structure to hold the certificate fields
typedef struct {
    char version[4];
    char serialNumber[20];
    char signatureAlgorithm[50];
    char issuer[256];
    char validityNotBefore[20];
    char validityNotAfter[20];
    char subject[256];
    char subjectPublicKeyInfo[512];
    int trustLevel;
} Certificate;

// A function to write the certificate to a file
void writeCertificate(const char *filename, const Certificate *cert) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        printf("Error opening file");
        return;
    }

    fprintf(file, "Version: %s\n", cert->version);
    fprintf(file, "Serial Number: %s\n", cert->serialNumber);
    fprintf(file, "Signature Algorithm: %s\n", cert->signatureAlgorithm);
    fprintf(file, "Issuer: %s\n", cert->issuer);
    fprintf(file, "Validity Not Before: %s\n", cert->validityNotBefore);
    fprintf(file, "Validity Not After: %s\n", cert->validityNotAfter);
    fprintf(file, "Subject: %s\n", cert->subject);
    fprintf(file, "Subject Public Key Info: %s\n", cert->subjectPublicKeyInfo);
    fprintf(file, "Trust Level: %d\n", cert->trustLevel);

    fclose(file);
}

// A function to read the certificate from a file
void readCertificate(const char *filename, Certificate *cert) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file.\n");
    }
    
    fscanf(file, "Version: %s\n", cert->version);
    fscanf(file, "Serial Number: %s\n", cert->serialNumber);
    fscanf(file, "Signature Algorithm: %s\n", cert->signatureAlgorithm);
    fscanf(file, "Issuer: %[^\\n]\n", cert->issuer);
    fscanf(file, "Validity Not Before: %s\n", cert->validityNotBefore);
    fscanf(file, "Validity Not After: %s\n", cert->validityNotAfter);
    fscanf(file, "Subject: %[^\\n]\n", cert->subject);
    fscanf(file, "Subject Public Key Info: %[^\\n]\n", cert->subjectPublicKeyInfo);
    fscanf(file, "Trust Level: %d", cert->trustLevel);

    fclose(file);
}

bool verifyCert(Certificate cert, char* currentDate, char* currentHash) {
    //returns true if cert is valid, false otherwise

    //Check if current date is before "valid not before" date
    if (strcmp(cert.validityNotBefore, currentDate) > 0) {
        printf("Cert is not valid. Current date is before certificate validity start.");
        return false;
    }

    //Check if current date is after "valid not after" date
    if (strcmp(cert.validityNotAfter, currentDate) > 0) {
        printf("Cert is not valid. Current date is after certificate validity end.");
        return false;
    }


    //Check if certificate hashes to the same value
    char storedHash[1000];
    FILE* hashFile = fopen("hash.txt", "r");
    fscanf(hashFile, "%s", storedHash);
    fclose(hashFile);

    if (strcmp(storedHash, currentHash) != 0) {
        printf("Cert is not valid. Cert has been modified - hashes do not match.");
        return false;
    }

    return true;
}

int main() {
    //Manually change the "current date" to check if certificate is within its valid timeframe
    char currentDate[] = "20231128204400";// YYYY MM DD HH MM SS

    // Read the certificate from the file
    Certificate readCert;
    readCertificate("certificate.txt", &readCert);

    Certificate cert = {
        .version = readCert.version,
        .serialNumber = readCert.serialNumber,
        .signatureAlgorithm = readCert.signatureAlgorithm,
        .issuer = readCert.issuer,
        .validityNotBefore = readCert.validityNotBefore,
        .validityNotAfter = readCert.validityNotAfter,
        .subject = readCert.subject,
        .subjectPublicKeyInfo = readCert.subjectPublicKeyInfo,
        .trustLevel = readCert.trustLevel
    };

    // Write the certificate to a file
    //writeCertificate("certificate.txt", &cert);

    // Print the read certificate to verify it was read correctly
    system("clear");
    printf("Read certificate:\n", 0);
    printf("Version: %s\n", readCert.version);
    
    // Hash the certificate

    FILE* certFile = fopen("certificate.txt", "r");
    if (!certFile) {
        printf("Unable to open certFile");
        return EXIT_FAILURE;
    }

    printf("AAAAA");
    bool flag = false;
    char c, ch;
    long long hashKey = 1234;
    keys(hashKey);

    do {
        c = fgetc(certFile);
        if (feof(certFile)) {
            break;
        }

        if(!flag) {
            ch = hash(c, hashKey);
            flag = true;
        } else {
            ch = hash(c, hashKey);
        }
    } while(1);

    fclose(certFile);

    unsigned char uch = ch;
    printf("Hash: %x", uch);

    FILE* hashFile = fopen("hash.txt", "w");
    fprintf(hashFile, "%c\n", uch);
    fclose(hashFile);

    bool certIsValid = verifyCert(cert, currentDate, uch);

   return 0;
}
