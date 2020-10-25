#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PATTERNS 100
#define MAX_KEY_LEN 100
#define MAX_STRING_LEN 841 //cipher files containing \n at the end --> 840+1

const char alpEnd=90;   //ascii Z
const char alpStart=65; //ascii A
FILE* plainTXTpt;

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

void vigenereCipher(char* arr,char* key){   //input arr must be string
    int i;
    for(i=0;i<strlen(arr)-1;i++){
        int c=(arr[i]-65)-(key[i%strlen(key)]-65);
        if(c < 0)   //instead of modulo operation
            c+=26;
        arr[i]=c%26+65;
    }
    char sample[strlen(arr)];
    strncpy(sample,arr,strlen(arr)-1);  //-1 to avoid \n
    if(find(sample,plainTXTpt)){
        printf("key: %s\n",key);
        printf("decrypted msg: %s\n",arr);
    }
}

void findPatterns(char* fname,int keyLen){
    FILE* fp=fopen(fname,"rt");
    if(fp==NULL){
        puts("error occurred while trying to create stream");
        return -1;
    }
    long size=calFileSize(fp);

    int i,j,k;
    char** str=(char**)malloc(sizeof(char*)*((int)size/6+1)); //2D array
    for(i=0;i<=(int)size/6;i++)
        str[i]=(char*)malloc(keyLen+1);

    for(i=0;i<=(int)size/6;i++)
        fgets(str[i],keyLen+1,fp);

    char patterns[MAX_PATTERNS][10]; int top=0;
    char* ptr;  char the[4]="the";
    for(i=0;i<=(int)size/6;i++){  //loop 2D array rows
        ptr=str[i];
        for(j=0;j<=keyLen-3;j++){    //loop columns
            int count=0;
            strncpy(the,ptr+j,3);
            if(strlen(the)!=3)  //trying to look for THE
                continue;

            for(k=0;k<=(int)size/6;k++)
                if(strstr(*(str+k)+j,the)) //look for match
                    count++;
            if(count>=2){
                int flag=0;
                for(k=0;k<top;k++){
                    if(strncmp(patterns[k],the,3)==0){
                        flag=1; //it is duplicate pattern
                        break;
                    }
                }
                if(!flag)
                    strcpy(patterns[top++],the);
            }
        }
    }
    puts("<PATTERNS FOUND>");
    for(i=0;i<top;i++)
        printf("%5s",patterns[i]);
    //freee
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
void decryptKey(char* arr,char* key,int* indexToFill,int r){
    int i,j;  int unknownspace=r;

    char startkey[MAX_KEY_LEN]="";  //variable sized obj not allowed
    for(i=0;i<unknownspace;i++)
        strncat(startkey,&alpStart,1);
    char endkey[MAX_KEY_LEN]="";
    for(i=0;i<unknownspace;i++)
        strncat(endkey,&alpEnd,1);

    char mergedKey[MAX_KEY_LEN]="";
    strcat(mergedKey,key);
    while(startkey[strlen(startkey)-1]!=alpEnd+1){ //while key is not endkey
        for(i=0;i<26;i++){
            for(j=0;j<unknownspace;j++)
                mergedKey[indexToFill[j]]=startkey[j];
            puts(mergedKey);

            vigenereCipher(arr,mergedKey);
            startkey[0]+=1;   //at the end key=']'
        }
        convertCarry(startkey);
    }
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
    findPatterns("cexercise3.txt",6);
    arr=readFile("cexercise3.txt");

    //int unknownIndexes[]={0,4,5};     //STT
    //decryptKey(arr,"AZMPAA",unknownIndexes,3);
    //int unknownIndexes[]={3,4,5};     //NSP
    //decryptKey(arr,"ULLAAA",unknownIndexes,3);
    //int unknownIndexes[]={0,1,5};     //PMF
    //decryptKey(arr,"AAWTBA",unknownIndexes,3);
    //int unknownIndexes[]={0,4,5};     //RPM
    //decryptKey(arr,"AYIIAA",unknownIndexes,3);
    return 0;
}
