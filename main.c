#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MAX_PATTERN_LEN 10   //HAVE, THAT, BE, ARE, IS, AND, THE ....
#define MAX_PATTERNS 100
#define MAX_KEY_LEN 100
#define MAX_STRING_LEN 842 //cipher files containing \n at the end --> 840+1

const char alpEnd=90;   //ascii Z
const char alpStart=65; //ascii A

typedef struct{
    int indexes[MAX_PATTERN_LEN];
    char patterns[MAX_PATTERN_LEN];
    int count;
}PATTERNS;

char* readFile(char* fname){
    FILE* fp=fopen(fname,"rt");
    if(fp==NULL){
        puts("error occurred while trying to create stream");
        return;
    }
    char* str=(char*)malloc(MAX_STRING_LEN);
    fgets(str,MAX_STRING_LEN,fp);   //read one line only

    fclose(fp);
    return str;
}

void caesarCipher(char* arr){
    int i,j;
    for(i=1;i<27;i++){  //alphabets
        char str[MAX_STRING_LEN]="";
        for(j=0;j<strlen(arr)-1;j++){ //index
            char c=(arr[j]+i-65)%26+65;
            strncat(str,&c,1);  //append char to string
        }
        printf("shift: %d\n%s\n",i,str);
    }
}

char* vigenereCipher(char* arr,char* key){   //2 string inputs
    int i;  char* tmp=malloc(MAX_STRING_LEN);
    strcpy(tmp,arr);
    for(i=0;i<strlen(arr)-1;i++){
        int c=(tmp[i]-65)-(key[i%strlen(key)]-65);
        if(c < 0)   //instead of modulo operation
            c+=26;
        tmp[i]=c%26+65;
    }
    return tmp;
}

PATTERNS* findPatterns(char* arr,int keyLen,int patternLen,int minCount){
    int size=strlen(arr);

    int i,j,k;
    char** str=(char**)malloc(sizeof(char*)*(size/keyLen)); //set 2D array
    for(i=0;i<=size/keyLen;i++)
        str[i]=(char*)malloc(keyLen+1);

    for(i=0;i<=size/keyLen;i++) //divide given text into key length
        strncpy(str[i],arr+keyLen*i,keyLen);

    PATTERNS* patterns=(PATTERNS*)malloc(MAX_PATTERNS*10); int top=0;
    char* ptr;
    char* the=(char*)malloc(patternLen+1);//any pattern found saved here
    for(i=0;i<=size/keyLen;i++){  //loop 2D array rows
        ptr=str[i];
        for(j=0;j<=keyLen-patternLen;j++){  //loop columns
            int count=0;
            strncpy(the,ptr+j,patternLen);
            if(strlen(the)!=patternLen)  //trying to look for pattern that meets patternLen argument
                continue;

            for(k=0;k<=size/keyLen;k++)
                if(strstr(*(str+k)+j,the)) //looks for match
                    count++;

            if(count>=minCount){
                int flag=0;
                for(k=0;k<top;k++){ //check duplicate pattern
                    if(strncmp(patterns[k].patterns,the,patternLen)==0){
                        flag=1; //if duplicate
                        break;
                    }
                }
                if(!flag){ //when it is a new pattern
                    patterns[top].count=count;
                    strcpy(patterns[top].patterns,the);
                    for(k=0;k<sizeof(patterns[top].indexes)/sizeof(int);k++)
                        patterns[top].indexes[k]=-1;
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

int getPatternTotal(PATTERNS* patterns){
    int i,total;
    for(i=0; strcmp(patterns[i].patterns,"") && i!=MAX_PATTERNS ;i++)
        total+=patterns[i].count;
    return total;
}
void convertCarry(char* key){
    int i;
    for(i=0;i<strlen(key)-1;i++){
        if(key[i]==(alpEnd+1)){
            key[i]=alpStart; //reset
            key[i+1]+=1; //carry
        }
    }
}
void decryptKey(char* arr,char* key,int* fixedIndex,int r,int minOccur){ //r=unkownspaces
    if(r==0){
        puts("there should be more than 1 unknown spaces");
        return;
    }
    int i,j,tested=0;

    char startkey[MAX_KEY_LEN]="";  //variable sized obj not allowed
    for(i=0;i<r;i++)
        strncat(startkey,&alpStart,1);
    char endkey[MAX_KEY_LEN]="";
    for(i=0;i<r;i++)
        strncat(endkey,&alpEnd,1);

    char mergedKey[MAX_KEY_LEN];
    for(i=0;i<strlen(key);i++) //merge known key into mergedKey
        mergedKey[fixedIndex[i]]=key[i];

    int maxNum=0;
    char outputString[MAX_STRING_LEN],outputKey[MAX_KEY_LEN];
    while(startkey[strlen(startkey)-1]!=alpEnd+1){ //while key is not endkey
        for(i=0;i<26;i++){ //every loop increase key (AAA -> AAB)
            int skip=0,take=0;  tested++;

            for(j=0;j<r+strlen(key);j++){ //merge known key into mergedKey
                if(j==fixedIndex[skip]){
                    skip++;
                    continue;
                }
                mergedKey[j]=startkey[take++];
            }

            /**
            looks for best fitting key by counting patterns on each decrypted msg
            correctly decrypted msg should have the highest number of patterns on same indexes
            ex) THE {0,1,2}
                OF {3,4}  HAVE {2,3,4,5}
           **/
            printf("\rsearching...%d tested",tested);
            char* decryptedTXT=vigenereCipher(arr,mergedKey);
            PATTERNS* pattINdecrypt=findPatterns(decryptedTXT,strlen(key)+r,strlen(key),minOccur);

            int patternNum=getPatternTotal(pattINdecrypt);
            if(patternNum>maxNum){
                maxNum=patternNum;
                strcpy(outputKey,mergedKey);
                strcpy(outputString,decryptedTXT);
            }
            free(decryptedTXT);
            startkey[0]+=1;   //at the end key=']'
        }
        convertCarry(startkey);
    }
    puts("\rBEST FITTING KEY IS......");
    printf("key: %s\n%s",outputKey,outputString);
}

char* keyFrom(char* ciphertxt,char* plaintxt){  //looks for key that converts plaintext to ciphertext
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

void printPatterns(PATTERNS* patterns){
    int i,j;    puts("<patterns found>");
    for(i=0; strcmp(patterns[i].patterns,"") && i!=MAX_PATTERNS ;i++){
        printf("%s: {",patterns[i].patterns);
        for(j=0; patterns[i].indexes[j]!=-1 ;j++)
            printf(" %d ",patterns[i].indexes[j]);
        printf("} %d\n",patterns[i].count);
    }puts("");
}

char* transPositionEncrypt(char* arr,int colLen,int* readOrder){
    int size=strlen(arr)-1; //-1 for \n
    int row=(size%colLen!=0)?size/colLen+1:size/colLen;

    int txtAt=0;
    char* transArr=(char*)calloc(row*colLen,sizeof(char));
    int i,j;
    for(i=0;i<row;i++){ //fills row by row
        for(j=0;j<colLen;j++){
            int index=colLen-1-j;  //index to read left -> right
            transArr[index*row+i]=arr[txtAt++]; //[index][i] fill [3][0] [2][0] [1][0] [0][0] (left to right)
        }
    }

    char* output=(char*)malloc(size);   output[0]=0; //initialize null (to navigate when strncat)
    //read column by column
    for(i=0;i<colLen;i++){
        int index=readOrder[colLen-1-i];  //readOrder from behind, transform readOrder to index
        for(j=0;j<row;j++){
            char c=transArr[index*row+j]; //[index][j] get [3][0] [3][1] [3][2] .....
            strncat(output,&c,1);
        }
    }

    free(transArr);
    return output;
}

char* transPositionDecrypt(char* arr,int colLen,int* readOrder){
    int size=strlen(arr)-1; //-1 for \n
    int row=(size%colLen!=0)?size/colLen+1:size/colLen;

    int txtAt=0;
    char* transArr=(char*)calloc(row*colLen,sizeof(char));
    int i,j;
    for(i=0;i<colLen;i++){ //fills each column
        int index=colLen-1-i; // n... 3 2 1      LEFT->RIGHT
        for(j=0;j<row;j++){
            transArr[index*row+j]=arr[txtAt++];
        }
    }

    char* output=(char*)malloc(size);   output[0]=0; //initialize null (to navigate when strncat)
    //read row by row
    for(i=0;i<row;i++){
        for(j=0;j<colLen;j++){
            int index=colLen-1-readOrder[j]; //convert readOrder to LEFT->RIGHT index
            char c=transArr[index*row+i]; //[index][i], column read order? ex) 3(E) 1(T) 2(H)
            strncat(output,&c,1);
        }
    }

    free(transArr);
    return output;
}

int main()
{
    int i;
    /*q1*/puts("---EXERCISE 1---");
    char* arr=readFile("cexercise1.txt");
    caesarCipher(arr);

    /*q2*/puts("---EXERCISE 2---");
    char* key="TESSOFTHEDURBERVILLES";
    arr=readFile("cexercise2.txt");
    char* answer=vigenereCipher(arr,key);
    printf("key: %s\n%s\n",key,answer);
    free(answer);

    /*q3*/puts("---EXERCISE 3---");
    arr=readFile("cexercise3.txt");
    int keyLen=6;   int minOccur=2;
    char* plaintxt="THAT"; //plain text to be substituted on patterns
    PATTERNS* patterns4=findPatterns(arr,keyLen,strlen(plaintxt),minOccur); //save 4 letter patterns found here

    printPatterns(patterns4);

    for(i=0; strcmp(patterns4[i].patterns,"") && i!=MAX_PATTERNS ;i++){  //FOR EVERY ELEMENT IN PATTERN ARRAY
        char* suspectedKey=keyFrom(patterns4[i].patterns,plaintxt); //assuming plaintxt matches pattern get corresponding key
        printf("\nsubstituting ciphertxt(%s) on plaintxt(%s), key=%s\n",patterns4[i].patterns,plaintxt,suspectedKey);
        decryptKey(arr,suspectedKey,patterns4[i].indexes,keyLen-strlen(plaintxt),minOccur);

        free(suspectedKey);
    }

    /*q4*/puts("---EXERCISE 4---");
    arr=readFile("cexercise4.txt");
    keyLen=4;   minOccur=5; //too many for 2, increased threshold to 3
    plaintxt="THE"; //plain text to be substituted on patterns
    PATTERNS* patterns3=findPatterns(arr,keyLen,strlen(plaintxt),minOccur); //save 3 letter patterns found here

    printPatterns(patterns3);

    for(i=0; strcmp(patterns3[i].patterns,"") && i!=MAX_PATTERNS ;i++){  //FOR EVERY ELEMENT IN PATTERN ARRAY
        char* suspectedKey=keyFrom(patterns3[i].patterns,plaintxt); //assuming plaintxt matches pattern get corresponding key
        printf("\nsubstituting ciphertxt(%s) on plaintxt(%s), key=%s\n",patterns3[i].patterns,plaintxt,suspectedKey);
        decryptKey(arr,suspectedKey,patterns3[i].indexes,keyLen-strlen(plaintxt),minOccur);

        free(suspectedKey);
    }

    /*q5*/puts("---EXERCISE 5---");
    arr=readFile("cexercise5.txt");
    keyLen=4;
    int order[keyLen];
    for(i=0;i<keyLen;i++)
        order[i]=i;
    char* decryptMsg=transPositionDecrypt(arr,keyLen,order);
    puts(decryptMsg); free(decryptMsg);

    return 0;
}
