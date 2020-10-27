#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN_COUNT_TO_BE_PATTERN 3
#define MAX_PATTERN_LEN 10   //HAVE, THAT, BE, ARE, IS, AND, THE ....
#define MAX_PATTERNS 100
#define MAX_KEY_LEN 100
#define MAX_STRING_LEN 841 //cipher files containing \n at the end --> 840+1

const char alpEnd=90;   //ascii Z
const char alpStart=65; //ascii A
FILE* plainTXTpt;

typedef struct{
    int indexes[MAX_PATTERN_LEN];
    char patterns[MAX_PATTERN_LEN];
}PATTERNS;

FILE* readPlainTXT(char* fname){
    FILE* fp=fopen(fname,"rt");
    if(fp==NULL){
        puts("error occurred while trying to create stream");
        return -1;
    }
    return fp;
}
long calFileSize(FILE* fp){
    long fpos=ftell(fp); //to be safe
    long size;

    fseek(fp,0,SEEK_END); //move pointer to the end of file
    size=ftell(fp); //ftell returns current location (bytes)

    fseek(fp,fpos,SEEK_SET); //RESET pointer

    return size;
}

char* readFile(char* fname){
    FILE* fp=fopen(fname,"rt");
    if(fp==NULL){
        puts("error occurred while trying to create stream");
        return -1;
    }
    char* str=(char*)malloc(MAX_STRING_LEN);
    fgets(str,MAX_STRING_LEN,fp);   //read one line only

    fclose(fp);
    return str;
}
int find(char* decrypt,FILE* fp){
    long curr=0; //initial file offset

    char str[MAX_STRING_LEN*2]; //going to save 2 lines
    char nxtln[MAX_STRING_LEN];
    while(fgets(str,MAX_STRING_LEN,fp)!=NULL){  //fgets always add \0 at the end
        curr+=MAX_STRING_LEN-1;
        fgets(nxtln,MAX_STRING_LEN,fp);
        strcat(str,nxtln);

        fseek(fp,curr,SEEK_SET); //offset retrieve 1 line
        if(strstr(str,decrypt)){
            fseek(fp,0,SEEK_SET); //reset file pointer
            //fclose(fp);
            return 1;
        }
    }
    fseek(fp,0,SEEK_SET);
    //fclose(fp);
    return 0;
}

void caesarCipher(char* arr){
    int i,j;
    for(i=1;i<27;i++){  //alphabets
        char str[MAX_STRING_LEN]="";
        char sample[100];
        for(j=0;j<strlen(arr);j++){ //index
            char c=(arr[j]+i-65)%26+65;
            strncat(str,&c,1);  //append char to string
        }
        strncpy(sample,str,100);    //strncpy does not copy string terminator
        if(find(sample,plainTXTpt)){
            printf("shift: %d\n",i);
            printf("decrypted msg: %s\n",str);
            return;
        }
    }
}

int vigenereCipher(char* arr,char* key){   //input arr must be string
    int i;
    for(i=0;i<strlen(arr)-1;i++){
        int c=(arr[i]-65)-(key[i%strlen(key)]-65);
        if(c < 0)   //instead of modulo operation
            c+=26;
        arr[i]=c%26+65;
    }
    char sample[30];
    strncpy(sample,arr,30);  //-1 to avoid \n
    if(find(sample,plainTXTpt)){
        printf("key: %s\n",key);
        printf("decrypted msg: %s\n",arr);
        return 1;
    }
    return 0;
}

PATTERNS* findPatterns(char* fname,int keyLen,int patternLen){
    FILE* fp=fopen(fname,"rt");
    if(fp==NULL){
        puts("error occurred while trying to create stream");
        return -1;
    }
    long size=calFileSize(fp);

    int i,j,k;
    char** str=(char**)malloc(sizeof(char*)*((int)size/keyLen)); //2D array
    for(i=0;i<=(int)size/keyLen;i++)
        str[i]=(char*)malloc(keyLen+1);

    for(i=0;i<=(int)size/keyLen;i++)
        fgets(str[i],keyLen+1,fp);

    PATTERNS* patterns=(PATTERNS*)malloc(MAX_PATTERNS*10); int top=0;
    char* ptr;  //char the[patternLen+1]="";
    char* the=(char*)malloc(patternLen+1);//any pattern found saved here
    for(i=0;i<=(int)size/keyLen;i++){  //loop 2D array rows
        ptr=str[i];
        for(j=0;j<=keyLen-patternLen;j++){    //loop columns
            int count=0;
            strncpy(the,ptr+j,patternLen);
            if(strlen(the)!=patternLen)  //trying to look for pattern that meets patternLen argument
                continue;

            for(k=0;k<=(int)size/keyLen;k++)
                if(strstr(*(str+k)+j,the)) //look for match
                    count++;

            if(count>=MIN_COUNT_TO_BE_PATTERN){
                int flag=0;
                for(k=0;k<top;k++){
                    if(strncmp(patterns[k].patterns,the,patternLen)==0){
                        flag=1; //it is duplicate pattern
                        break;
                    }
                }
                if(!flag){
                    strcpy(patterns[top].patterns,the);
                    for(k=0;k<strlen(the);k++)
                        patterns[top].indexes[k]=j+k;
                    top++;
                }
            }
        }
    }
    free(the);
    free(str);
    return patterns;
}

void convertCarry(char* key){
    int i;
    for(i=0;i<strlen(key)-1;i++){
        if(key[i]==(alpEnd+1)){
                //puts("carry detected");
            key[i]=alpStart; //reset
            key[i+1]+=1; //carry
        }
    }
}
int decryptKey(char* arr,char* key,int* fixedIndex,int r){ //r=unkownspaces
    int i,j,tested=0;

    char startkey[MAX_KEY_LEN]="";  //variable sized obj not allowed
    for(i=0;i<r;i++)
        strncat(startkey,&alpStart,1);
    char endkey[MAX_KEY_LEN]="";
    for(i=0;i<r;i++)
        strncat(endkey,&alpEnd,1);

    char mergedKey[MAX_KEY_LEN];
    for(i=0;i<strlen(key);i++)
        mergedKey[fixedIndex[i]]=key[i];

    while(startkey[strlen(startkey)-1]!=alpEnd+1){ //while key is not endkey
        for(i=0;i<26;i++){
            int skip=0,take=0;  tested++;
            for(j=0;j<r+strlen(key);j++){
                if(j==fixedIndex[skip]){
                    skip++;
                    continue;
                }
                mergedKey[j]=startkey[take++];
            }
            printf("\r%s, %d tested so far",mergedKey,tested);

            if(vigenereCipher(arr,mergedKey))
                return 1;
            startkey[0]+=1;   //at the end key=']'
        }
        convertCarry(startkey);
    }puts("");
    return 0;
}

char* keyFrom(char* ciphertxt,char* plaintxt){  //ciphertxt + key  ->  "THE"
    char* key=(char*)malloc(strlen(ciphertxt)+1);
    int i;
    for(i=0;i<strlen(ciphertxt);i++){
        int shift=(ciphertxt[i]-65)-(plaintxt[i]-65);
        if(shift < 0)   //instead of modulo operation
            shift+=26;
        key[i]=shift%26+65;
    }
    return key;
}

int main()
{
    plainTXTpt=readPlainTXT("tess26.txt");
    /*q1*/puts("---EXERCISE 1---");
    char* arr=readFile("cexercise1.txt");
    caesarCipher(arr);

    /*q2*/puts("---EXERCISE 2---");
    char* key="TESSOFTHEDURBERVILLES";
    arr=readFile("cexercise2.txt");
    vigenereCipher(arr,key);

    /*q3*/puts("---EXERCISE 3---");
    arr=readFile("cexercise3.txt");
    int keyLen=6;
    char* plaintxt="THE"; //plain text to be substituted by patterns tested
    PATTERNS* patterns=findPatterns("cexercise3.txt",keyLen,strlen(plaintxt)); //for each patterns it takes about 190 sec to test all possibilities

    //PRINT PATTERNS
    int i,j;    puts("<patterns found>");
    for(i=0; strcmp(patterns[i].patterns,"") && i!=MAX_PATTERNS ;i++){
        printf("%s: {",patterns[i].patterns);
        for(j=0; j<strlen(plaintxt) ;j++)
            printf(" %d ",patterns[i].indexes[j]);
        printf("}              ");
    }puts("");

    for(int i=0; strcmp(patterns[i].patterns,"") && i!=MAX_PATTERNS ;i++){
        //printf("%s: {%d %d %d}\n",patterns[i].patterns,patterns[i].indexes[0],patterns[i].indexes[1],patterns[i].indexes[2]);
        char* suspectedKey=keyFrom(patterns[i].patterns,plaintxt);
        printf("substituting ciphertxt(%s) on plaintxt(%s)\n",patterns[i].patterns,plaintxt);
        if(decryptKey(arr,suspectedKey,patterns[i].indexes,keyLen-strlen(plaintxt))){
            free(suspectedKey);
            break;
        }
        free(suspectedKey);
    }

    return 0;
}
