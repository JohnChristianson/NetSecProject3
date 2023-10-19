#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {

    struct signatureAlgIdentifier {
        int algorithm;          // Algorithm
        int params;             // Parameters
    };

    struct validity {
        int startDate;          // Period of validity start
        int endDate;            // Period of validity end
    };

    struct subjectInfo {
        int algorithms;         // Algorithms
        int params;             // Parameters
        int key;                // Key
    };

    struct signature {
        int algs;
        int params;
        int signature;
    };

    struct certificate {
        int version;            // Version
        int serialNumber;       // Certificate serial number.

        // Signature algorithm identifier
        struct signatureAlgIdentifier sigAlgIdent;

        char issuerName[100];   // Issuer name

        // Period of validity
        struct validity validPeriod;

        char subjectName[100];  // Subject name

        // Subject public key info
        struct subjectInfo subInfo;

        // Signature
        struct signature sig;

        short TL;                 // Trust level
    };

    struct certificate cert;

    printf("Enter Version Number: ");
    scanf("%d", &cert.version);

    printf("\nEnter Certificate Serial Number: ");
    scanf("%d", &cert.serialNumber);

    printf("\nEnter Signature Algorithm Identifier - Algorithm: ");
    scanf("%d", &cert.sigAlgIdent.algorithm);

    printf("\nEnter Signature Algorithm Identifier - Parameters: ");
    scanf("%d", &cert.sigAlgIdent.params);

    printf("\nEnter Issuer Name: ");
    scanf("%s", cert.issuerName);

    printf("\nEnter Period of Validity Start: ");
    scanf("%d", &cert.validPeriod.startDate);

    printf("\nEnter Period of Validity End: ");
    scanf("%d", &cert.validPeriod.endDate);

    printf("\nEnter Subject Name");
    scanf("%s", &cert.subjectName);

    printf("\nEnter Subject Public Key Info - Algorithms: ");
    scanf("%d", &cert.subInfo.algorithms);

    printf("\nEnter Subject Public Key Info - Parameters: ");
    scanf("%d", &cert.subInfo.params);

    printf("\nEnter Subject Public Key Info - Key: ");
    scanf("%d", &cert.subInfo.key);

    printf("\n Enter Signature Algorithms: ");
    scanf("%d", cert.sig.algs);

    printf("\n Enter Signature Parameters: ");
    scanf("%d", cert.sig.params);   

    printf("\n Enter Signature: ");
    scanf("%d", cert.sig.signature);


    return 0;
}