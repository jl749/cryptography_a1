#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEY_LEN 100
#define MAX_STRING_LEN 841 //cipher files containing \n at the end --> 840+1

const char alpEnd=90;   //ascii Z
const char alpStart=65; //ascii A

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
int find(char* decrypt){
    FILE* fp=fopen("tess26.txt","rt");  long curr=0; //initial file offset
    if(fp==NULL){
        puts("error occurred while trying to create stream");
        return -1;
    }
    char str[MAX_STRING_LEN*2]; //going to save 2 lines
    char nxtln[MAX_STRING_LEN];
    while(fgets(str,MAX_STRING_LEN,fp)!=NULL){  //fgets always add \0 at the end
        curr+=MAX_STRING_LEN-1;
        fgets(nxtln,MAX_STRING_LEN,fp);
        strcat(str,nxtln);

        fseek(fp,curr,SEEK_SET); //offset retrieve 1 line
        if(strstr(str,decrypt)){
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
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
        if(find(sample)){
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
    if(find(sample)){
        printf("key: %s\n",key);
        printf("decrypted msg: %s\n",arr);
    }
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
void decryptKey(char* arr,int keyLen){
    int i;
    char key[MAX_KEY_LEN]=""; //variable sized obj may not be initialized
    for(i=0;i<keyLen;i++)
        strncat(key,&alpStart,1); //strcat null terminator always

    char endkey[MAX_KEY_LEN]="";
    for(i=0;i<keyLen;i++)
        strncat(endkey,&alpEnd,1);

    while(strcmp(key,endkey)){ //while key is not endkey
        for(i=0;i<26;i++){
                puts(key);
            vigenereCipher(arr,key);
            key[0]+=1;   //at the end key=']'
        }
        convertCarry(key);
    }
}

int main()
{
    /*q1*/puts("---EXERCISE 1---");
    char* arr=readFile("cexercise1.txt");
    caesarCipher(arr);

    /*q2*/puts("---EXERCISE 2---");
    char* key="TESSOFTHEDURBERVILLES";
    arr=readFile("cexercise2.txt");
    vigenereCipher(arr,key);

    /*q3*/puts("---EXERCISE 3---");
    arr=readFile("cexercise3.txt");
    decryptKey(arr,6);
    return 0;
}
