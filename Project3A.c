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

    
}