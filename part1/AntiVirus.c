#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//////////////////////////////Constants//////////////////////////////
#define MAX_CHOICE_LENGTH 16










//////////////////////////////Structs//////////////////////////////

// Define the virus struct
typedef struct virus
{
    unsigned short SigSize; // the size of the signature
    char virusName[16];     // the name of the virus
    unsigned char *sig;     // signature of the virus (max size of 250 bytes)
} virus;

// Define the link struct
typedef struct link
{
    struct link *nextVirus;
    virus *vir;
} link;

// Define the function descriptor struct
typedef struct fun_desc
{
    char *name;
    void (*fun)(void);
} fdesc;









//////////////////////////////Global Variables//////////////////////////////
int debugMode = 0; // Debug mode flag
int endian = 0;    // Endian flag (0 for little endian, 1 for big endian)

char fileNameSig[256];       // Signature file name                 For loadsignatures and print signatures
FILE *signature_File = NULL; // Signature file pointer              For loadsignatures and print signatures

FILE *suspected_File = NULL;      // Suspected file pointer         For fixFile and detectFile
char suspected_File_Name[256]; // Suspected file name               For fixFile and detectFile

link *virus_list = NULL; // Head of the linked list                

int virus_array[10000] = {0}; // Array for the file content
int virus_array_size = 0;      // Size of the Array



//////////////////////////////Functions Decleration//////////////////////////////
void handleExit(char *msg, int errKind, int toExit, int errCode, int exit_kind);

// 1A//
virus *readVirus(FILE *file);
void printVirus(virus *v, FILE *output);
int validateMagicNumber(FILE *file);

// 1B//
void list_print(link *virus_list, FILE *output);  /* Print the data of every link in list to the given stream. Each item followed by a newline character. */
link *list_append(link *virus_list, virus *data); /* Add a new link with the given data to the list (at the end CAN ALSO AT BEGINNING),
                                                   and return a pointer to the list (i.e., the first link in the list).
                                                    If the list is null - create a new entry and return a pointer to the entry. */

void list_free(link *virus_list); /* Free the memory allocated by the list. */

link *loadSignatures(FILE *file); /* Load signatures from a file */
void LoadSignatures();            /* Calls loadSignatures */

void PrintSignatures(); /* Calls list_print */

void DetectViruses();                                             /* Detect viruses in a file */
void detect_virus(char *buffer, unsigned int size, link *v_List); /* Detect viruses in a buffer */

void FixFile();                                          /* Fix a file */
void netural_virus(char *fileName, int signitureOffset); /* Fix a file */

void quit(); /* Exit the program */









//////////////////////////////Main//////////////////////////////

int main(int argc, char *argv[])
{

    /*
    if (argc < 2)
    {
        printf("Usage: %s <file> [-d]\n", argv[0]);
        return 1;
    }
    
    memccpy(suspected_File_Name, argv[1], 0, strlen(argv[1])); // copy the file name to the global variable

    // Safely copy the string
    strncpy(suspected_File_Name, argv[1], strlen(argv[1]) + 1);


    suspected_File = fopen(argv[1], "rb");
    
    // Check if a file is loaded successfully
    if (!suspected_File)
    {
        fprintf(stderr, "Error: cannot open file\n");
        return 1;
    }

    // Check if the user wants to run in debug mode
    if (argc == 3 && strcmp(argv[2], "-d") == 0)
        debugMode = 1;

    strcpy(fileNameSig, "signatures-L");
    signature_File = fopen(fileNameSig, "rb");
*/
    char input[256]; // Buffer for user input
    int choice;
    char *endptr;

    fdesc funcs[] = {{"Load signatures", LoadSignatures},
                     {"Print signatures", PrintSignatures},
                     {"Detect viruses", DetectViruses},
                     {"Fix file", FixFile},
                     {"Quit", quit},
                     {NULL, NULL}};

    while (!feof(stdin))
    {
        // Display menu
        printf("Select operation from the following menu:\n");

        int bound = sizeof(funcs) / sizeof(funcs[0]) - 1;
        for (int i = 0; i < bound; i++)
            printf("%i: %s\n", i, funcs[i].name);

        printf("\nEnter your choice: ");

        // Read user input
        if (fgets(input, 16, stdin))
        {
            choice = strtol(input, &endptr, 10); // convert the input to int

            // Validate input

            if (endptr == input || *endptr != '\n') // Check if the input is a number
            {
                printf("Invalid input\n");
                continue;
            }

            else if (choice < 0 || choice >= bound) // Check if the input is within bounds
            {
                printf("Not within bounds\n");
                continue;
            }

            // Perform the selected operation
            else
            {
                funcs[choice].fun();
            }
        }
        else
        {
            fprintf(stderr, "Error: reading from input\n");
        }
    }
}



/**
 * Function: readVirus
 * --------------------
 * Reads a virus from a file
 *
 * file: the file to read from
 *
 * returns: a pointer to the virus
 */
virus *readVirus(FILE *file)
{
    if (feof(file))
        return NULL;

    virus *v = (virus *)malloc(sizeof(virus));

    if (debugMode)
        printf("[DEBUG] Read virus: %s (SigSize: %d)\n", v->virusName, v->SigSize);
    

    // Check if memory allocation was successful
    if (!v)
    {
        fprintf(stderr, "Error: memory allocation failed\n"); // Print error message
        return NULL;
    }

    // Read the first 18 bytes
    if (fread(v, 1, 18, file) != 18)
    {
        free(v);
        return NULL; // End of file or read error
    }

    if (v->SigSize == 0)
    {
        free(v);
        return NULL;
    }

    if (endian) // Big Endian
    {
        v->SigSize = ((v->SigSize) >> 8) | ((v->SigSize) << 8);
    }

    if (v->SigSize > 1000 & debugMode)
    {
        fprintf(stderr, "Error: signature size of %i is big\n", v->SigSize);
    }

    // Allocate memory for signature
    v->sig = (unsigned char *)malloc(v->SigSize);

    // Check if memory allocation was successful
    if (!v->sig)
    {
        free(v);
        fprintf(stderr, "Error: memory allocation failed\n");
        return NULL;
    }

    // Read the signature
    if (fread(v->sig, 1, v->SigSize, file) != v->SigSize)
    {
        free(v->sig);
        free(v);
        return NULL;
    }

    return v;
}

/*
 * Function: printVirus
 * --------------------
 * Prints a virus to a file
 *
 * v: the virus to print
 * output: the file to print to
 */
void printVirus(virus *v, FILE *output)
{
    fprintf(output, "Virus name in Hexa: %d\n", v->virusName);
    fprintf(output, "Virus name : %s\n", v->virusName);
    fprintf(output, "Virus size: %d\n", v->SigSize);
    fprintf(output, "Signature:\n");

    for (int i = 0; i < v->SigSize; i++)
        fprintf(output, "%02X ", v->sig[i]);

    fprintf(output, "\n\n");
}

/*
 * Function: validateMagicNumber
 * --------------------
 * Validates the magic number of a file
 *
 * file: the file to validate
 *
 * returns: 1 if the magic number is valid, 0 otherwise
 */
int validateMagicNumber(FILE *file)
{
    char magic[4];
    if (fread(magic, 1, 4, file) != 4)
    {
        fprintf(stderr, "Error reading magic number.\n");
        return 0;
    }

    if (strncmp(magic, "VIRL", 4) != 0 && strncmp(magic, "VIRB", 4) != 0)
    {
        fprintf(stderr, "Invalid magic number: %c%c%c%c\n", magic[0], magic[1], magic[2], magic[3]);
        return 0;
    }

    return 1;
}

/*

 *  Handle Exit Function
 *
 *  msg - Error Message
 *  errKind - Error Kind (1 for perror, 0 for fprintf)
 *  toExit - Exit the program or not
 *  errCode - Error Code
 *  exit_kind - 0 for _exit, 1 for exit
*/
void handleExit(char *msg, int errKind, int toExit, int errCode, int exit_kind)
{
    if (msg != NULL)
        if (errKind)
            perror(msg);
        else
            fprintf(stderr, "%s\n", msg);

    if (toExit)
        if (exit_kind)
            exit(errCode);
        else
            _exit(errCode);
}



/**
 * Function: list_append
 * --------------------
 * Appends a virus to a list
 *
 * virus_list: the list to append to
 * data: the virus to append
 *
 * returns: the new list
 */
link *list_append(link *virus_list, virus *data)
{
    link *newLink = (link *)malloc(sizeof(link));
    if (!newLink)
        return NULL;

    newLink->vir = data;
    newLink->nextVirus = virus_list;

    return newLink;
}

/*
 * Function: list_print
 * --------------------
 * Frees a list of viruses
 *
 * virus_list: the list to free
 */
void list_free(link *virus_list)
{
    link *current = virus_list;
    while (current != NULL)
    {
        link *next = current->nextVirus;
        free(current->vir->sig); // Free the signature
        current->vir->sig = NULL;
        free(current->vir);      // Free the virus
        current->vir = NULL;
        free(current);           // Free the link
        current = next;
    }
    // dont need to assign current to Null because in this point after the while loop -> current is already NULL
}


/**
 * Load signatures from a file
 */
void LoadSignatures()
{
    if(signature_File == NULL)
        {   
            fprintf(stdout, "Enter the signature file name: ");
            if(fgets(fileNameSig, 256, stdin) == NULL)
            {
                fprintf(stderr, "Error: reading from input\n");
                return;
            }
            fileNameSig[strcspn(fileNameSig, "\n")] = '\0'; // Remove the newline character
            signature_File = fopen(fileNameSig, "rb");      // Open the file

            if (!signature_File)
            {
                fprintf(stderr, "Error: cannot open file\n");
                return;
            }

            virus_list = loadSignatures(signature_File);

        }

    else
        {
            fprintf(stdout, "Alredy have file to take signatures from: %s", fileNameSig );
        }
    
}

/**
 * Load signatures from a file
 *
 * filename: the name of the file to load
 * virus_list: the list to append the viruses to
 *
 * returns: the new list
 */
link *loadSignatures(FILE *file)
{
    // check if the file is starts with the magic numbers for virus signatures
    char sig[5] = {0};
    fread(sig, 1, 4, file);       // read the first 4 bytes
    if (strcmp(sig, "VIRL") == 0) // check if the signature is little endian
        endian = 0;
    else if (strcmp(sig, "VIRB") == 0) // check if the signature is big endian
        endian = 1;
    else
    {
        fprintf(stderr, "Error: no virus signature\n");
        return NULL;
    }

    // read the signatures
    virus *v;
    link *head = NULL;

    while ((v = readVirus(file)))
        head = list_append(head, v);

    fseek(file, 0, SEEK_SET); // reset the file pointer
    return head;
}




/** 
    * Function: PrintSignatures
    * --------------------
    * Prints the signatures
*/
void PrintSignatures()
{
    list_print(virus_list, stdout);
}

/**
 * Function: list_print
 * --------------------
 * Prints a list of viruses
 *
 * virus_list: the list to print
 * output: the file to print to
 */
void list_print(link *virus_list, FILE *output)
{
    link *current = virus_list;
    while (current != NULL)
    {
        printVirus(current->vir, output);
        current = current->nextVirus;
    }
}


// Detect viruses in a file
void DetectViruses()
{

    suspected_File = NULL;
    for (int i = 0; i < virus_array_size; i++)
    {
        virus_array[i] = 0;
    }
    
    virus_array_size = 0;     // Size of the Array
    


    fprintf(stdout, "Enter the suspected file name: ");
    if(fgets(suspected_File_Name, 256, stdin) == NULL)
    {
        fprintf(stderr, "Error: reading from input\n");
        return;
    }
    suspected_File_Name[strcspn(suspected_File_Name, "\n")] = '\0'; // Remove the newline character
    suspected_File = fopen(suspected_File_Name, "rb");      // Open the file

    if (suspected_File == NULL)
    {
        fprintf(stderr, "Error: cannot open file\n");
        return;
    }





    // Check if signatures are loaded
    if (!virus_list)
    {
        fprintf(stderr, "Error: no signatures loaded\n");
        return;
    }

    char buffer[10000];
    int reader;

    fseek(suspected_File, 0, SEEK_SET); // reset the file pointer if called few times

    // Read the file
    if (!(reader = fread(buffer, 1, 10000, suspected_File)))
    {
        fprintf(stderr, "Error: reading file\n");
        return;
    }

    detect_virus(buffer, reader, virus_list); // Detect viruses in the buffer

    fclose(suspected_File);
    
}

// Detect viruses in a buffer
void detect_virus(char *buffer, unsigned int size, link *virus_list)
{
    link *current = virus_list;

    while (current != NULL)
    {
        virus *v = current->vir;

        // Iterate through the buffer and compare signatures
        for (unsigned int i = 0; i <= size - v->SigSize; i++)
        {
            if (memcmp(buffer + i, v->sig, v->SigSize) == 0)
            {
                // Virus detected
                printf("\n");
                printf("Virus detected!\n");
                printf("Starting byte: %d\n", i);
                printf("Virus name: %s\n", v->virusName);
                printf("Virus size: %u\n\n", v->SigSize);

                  // Store the offset in the global array
                if (virus_array_size < sizeof(virus_array)) {
                    virus_array[virus_array_size++] = i;
                } else {
                    fprintf(stderr, "Warning: virus_array is full, cannot store more offsets\n");
                }
            }
        }
        current = current->nextVirus;
    }

    if (virus_array_size == 0)
    {
        printf("No viruses detected\n");
    }
}





/**
    * Function: FixFile
    * --------------------
    * Fix a file
    *
 */
void FixFile()
{

    // Check if signatures are loaded
    if (!virus_list)
    {
        fprintf(stderr, "Error: no signatures loaded\n");
        return;
    }

    fprintf(stdout, "Fixing file: %s\n", suspected_File_Name);

    link *current = virus_list;
    for(int i = 0; i < virus_array_size; i++)
    {
        fprintf(stdout, "Neutralizing virus at offset %d\n", virus_array[i]);
        netural_virus(suspected_File_Name, virus_array[i]);
    }
}

/**
 * Function: netural_virus
 * --------------------
 * Neutralizes a virus in a file
 */
void netural_virus(char *fileName, int signatureOffset)
{
    FILE *file = fopen(fileName, "rb+");
    if (!file)
    {
        fprintf(stderr, "Error: cannot open file\n");
        return;
    }

    if (fseek(file, signatureOffset, SEEK_SET))
    {
        fprintf(stderr, "Error: cannot seek to offset\n");
        fclose(file);
        return;
    }

    unsigned char neutralized_signature = 0xC3;
    
   size_t bytes_written = fwrite(&neutralized_signature, sizeof(unsigned char), 1, file);
    if (bytes_written != 1) // Check if fwrite succeeded
    {
        fprintf(stderr, "Error: cannot write to file\n");
        fclose(file);
        return;
    }

    fprintf(stdout, "Virus neutralized at offset %d\n", signatureOffset);

    fclose(file);

}


// Quit Function - Exit the program
/**
    * Function: quit
    * --------------------
    * Free the memory and exit the program
    
*/
void quit()
{

    list_free(virus_list);
    if (signature_File)
    {
        fclose(signature_File);
        signature_File = NULL;
    }
    if (suspected_File)
    {
        fclose(suspected_File);
        suspected_File = NULL;
        }

    exit(0);
}