#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_STRING_LEN 841 //cipher files containing \n at the end --> 840+1

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
        strncpy(sample,str,100);
        if(find(sample)){
            printf("shift: %d\n",i);
            printf("%s\n",str);
            return;
        }
    }
}

void vigenereCipher(char* arr,char* key){
    int i;
    for(i=0;i<strlen(arr)-1;i++){
        int c=(arr[i]-65)-(key[i%strlen(key)]-65);
        if(c < 0)
            c+=26;
        arr[i]=c%26+65;
    }
    printf("%s\n",arr);
}

int main()
{
    /*q1*/
    char* arr=readFile("cexercise1.txt");
    caesarCipher(arr);

    /*q2*/
    char* key="TESSOFTHEDURBERVILLES";
    arr=readFile("cexercise2.txt");
    vigenereCipher(arr,key);

    /*q3*/
    return 0;
}
