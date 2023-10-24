#include <stdio.h>
#include <stdlib.h>

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
} Certificate;

// A function to write the certificate to a file
void writeCertificate(const char *filename, const Certificate *cert) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        printf("Error opening file.\n");
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

    fclose(file);
}

// A function to read the certificate from a file
void readCertificate(const char *filename, Certificate *cert) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file.\n");
        return;
    }

    fscanf(file, "Version: %s\n", cert->version);
    fscanf(file, "Serial Number: %s\n", cert->serialNumber);
    fscanf(file, "Signature Algorithm: %s\n", cert->signatureAlgorithm);
    fscanf(file, "Issuer: %[^\\n]\n", cert->issuer);
    fscanf(file, "Validity Not Before: %s\n", cert->validityNotBefore);
    fscanf(file, "Validity Not After: %s\n", cert->validityNotAfter);
    fscanf(file, "Subject: %[^\\n]\n", cert->subject);
    fscanf(file, "Subject Public Key Info: %[^\\n]\n", cert->subjectPublicKeyInfo);

    fclose(file);
}

int main() {
    // Write the certificate to a file
    //writeCertificate("certificate.txt", &cert);

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
        .subjectPublicKeyInfo = readCert.subjectPublicKeyInfo
    };

    // Print the read certificate to verify it was read correctly
    printf("Read certificate:\n");
    printf("Version: %s\n", readCert.version);

   return 0;
}
