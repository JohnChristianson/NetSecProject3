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
    Certificate cert = {
        .version = "1",
        .serialNumber = "1234567890",
        .signatureAlgorithm = "sha256WithRSAEncryption",
        .issuer = "CN=Test Certificate Authority,O=Test Org,C=US",
        .validityNotBefore = "20230101000000Z",
        .validityNotAfter = "20240101000000Z",
        .subject = "CN=Test Subject,O=Test Org,C=US",
        .subjectPublicKeyInfo = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtvr9T8ZU2HKSig..."
    };

    // Write the certificate to a file
    writeCertificate("certificate.txt", &cert);

    // Read the certificate from the file
    Certificate readCert;
    readCertificate("certificate.txt", &readCert);

    // Print the read certificate to verify it was read correctly
    printf("Read certificate:\n");
    printf("Version: %s\n", readCert.version);
    
   // ... repeat for other fields ...

   return 0;
}
