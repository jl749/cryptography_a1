#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <windows.h>

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

    char* output=(char*)malloc(size+1);   output[0]='\0'; //initialize null (to navigate when strncat)
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

/*no string argument on this func*/
void findSequence(char* arr,int arrLen,char* searchWord,int wordLen,char* mainArr){  //("ATAHTZ",6,"THAT",4) -->  {1,3,0,4}
    int mindex=0;   int index=0;
    int i,j,k;
    int* missingSeq=calloc(arrLen-wordLen,sizeof(int)); //contains unused index (sequence')
    int* sequence=calloc(wordLen,sizeof(int)); //contains indexes of arr (represent read order)

    /*fill sequence*/
    for(i=0;i<wordLen;i++){ // 0~4
        int found=0;
        for(j=0;j<arrLen;j++){ // 0~6
            //duplicate index check
            int flag=0;
            for(k=0;k<index;k++)
                if(sequence[k]==j)
                    flag=1;
            if(flag==1)
                continue;

            //go through searchWord for match
            if(arr[j]==searchWord[i]){
                sequence[index++]=j;    found=1;
                break;
            }
        }
        if(found==0) //all 4 letters need to be found in order to proceed
            return;
    }

    /*fill missingSequence*/
    for(i=0;i<arrLen;i++){ // 0~6
        int found=0;
        for(j=0;j<wordLen;j++){ //0~4
            if(i==sequence[j])
                found=1;
        }
        if(found==0)
            missingSeq[mindex++]=i;
    }

    //print
    fputs("\nfound sequence: ",stdout);
    for(i=0;i<wordLen;i++){
        printf("%d ",sequence[i]);
    }puts("");
    fputs("extr: ",stdout);
    for(i=0;i<mindex;i++){
        printf("%d ",missingSeq[i]);
    }puts("\n");

    free(missingSeq);
    free(sequence);
}
/**
    print possible sequences using matching word
    ex) keylen=6 , "THAT" -> find row containing T,H,A,T
    test all possible transposition using this sequence (total 6 cases)
**/
void findReadOrder(char* arr,int colLen,char* that){
    int size=strlen(arr)-1; //-1 for \n
    int row=(size%colLen!=0)?size/colLen+1:size/colLen;

    int txtAt=0;

    char transArr[colLen][row];
    int i,j;
    for(i=0;i<colLen;i++){ //fills each column
        int index=colLen-1-i; // n... 3 2 1      LEFT->RIGHT
        for(j=0;j<row;j++){
            transArr[index][j]=arr[txtAt++];
        }
    }

    char rotateArr[row][colLen];
    for(i=0;i<row;i++){ //rotate transArr 90 clockwise
        for(j=0;j<colLen;j++){
            int index=colLen-1-j;
            rotateArr[i][j]=transArr[index][i];
        }
    }
    //findSequence, loop and try arr[0] [1] ...
    for(i=0;i<row;i++){
        printf("\r<matching pattern found at row %d...>",i);
        findSequence(rotateArr[i],colLen,that,strlen(that),arr);
    }
    /**
        sequence 412 occurs 3 times, 123 occurs 5 times, 235 occurs 3 times
        hence when these three connected -> 41235   test 041235 and 412350
    **/
}

void printFrequency(char* arr){ //print letter frequency in given text
    int i;  char j;
    int countArr[26]; //array declared in functions = elements undefined
    for(i=0;i<sizeof(countArr)/sizeof(int);i++) //set elements 0
        countArr[i]=0;
    for(i=0;i<strlen(arr);i++)
        for(j=65;j<91;j++)
            if(j==arr[i]){
                countArr[j-65]+=1;
                break; //next letter
            }

    for(i=0;i<sizeof(countArr)/sizeof(int);i++)
        printf("%2c: %3d   ",i+65,countArr[i]);
    puts("");
}

//code from https://stackoverflow.com/questions/29574849/how-to-change-text-color-and-console-color-in-codeblocks
void SetColor(int ForgC)
{
     WORD wColor;
                          //We will need this handle to get the current background attribute
     HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
     CONSOLE_SCREEN_BUFFER_INFO csbi;

                           //We use csbi for the wAttributes word.
     if(GetConsoleScreenBufferInfo(hStdOut, &csbi))
     {
                     //Mask out all but the background attribute, and add in the forgournd color
          wColor = (csbi.wAttributes & 0xF0) + (ForgC & 0x0F);
          SetConsoleTextAttribute(hStdOut, wColor);
     }
     return;
}
void testSubstitut(char* arr,char (*substit)[2],int len){
    int i,j;
    for(i=0;i<strlen(arr);i++){
        int flag=0;
        for(j=0;j<len;j++){
                //printf("compare %c, %c\n",arr[i],substit[j][0]);
            if(arr[i]==substit[j][0]){
                if(substit[j][1]=='|')  //'|' won't be seen
                    SetColor(0);
                else
                    SetColor(12);
                printf("%c",substit[j][1]);
                SetColor(15);
                flag=1;
                break;
            }
        }
        if(flag==0)
            printf("%c",arr[i]);    //when no match
    }
    puts("");
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
        char* suspectedKey=keyFrom(patterns4[i].patterns,plaintxt); //assuming plaintxt matches given pattern get corresponding key
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
        char* suspectedKey=keyFrom(patterns3[i].patterns,plaintxt); //assuming plaintxt matches given pattern, get corresponding key
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
    puts(decryptMsg);
    free(decryptMsg);

    /*q6*/puts("---EXERCISE 6---");
    arr=readFile("cexercise6.txt");
    keyLen=6;
    findReadOrder(arr,keyLen,"THE");
    //findReadOrder(arr,keyLen,"WOULD"); also works (faster)

    int testOrder1[6]={0,4,1,2,3,5};
    int testOrder2[6]={4,1,2,3,5,0};puts("\rtest {0,4,1,2,3,5}                          ");
    decryptMsg=transPositionDecrypt(arr,keyLen,testOrder1);
    puts(decryptMsg);
    free(decryptMsg);puts("test {4,1,2,3,5,4}");
    decryptMsg=transPositionDecrypt(arr,keyLen,testOrder2);
    puts(decryptMsg);
    free(decryptMsg);

    /*q7*/puts("---EXERCISE 7---");
    arr=readFile("cexercise7.txt");
    printFrequency(arr);
    /**
    J:152, L:82, F:72, H:59, G:55  --> J=|, L=E, F=T, H=A
    A;0, C:0, K:1, T:0  --> k=Z,Q,J,X
    */
    char substit1[4][2]={{'J','|'}, {'L','E'}, {'F','T'}, {'H','I'}};
    testSubstitut(arr,substit1,4);
    /**
    repeating pattern TME found HENCE, M=H
    */
    char substit2[5][2]={{'J','|'},{'L','E'},{'F','T'},{'H','I'},{'M','H'}};
    testSubstitut(arr,substit2,5);
    /**
    pattern THEIO found HENCE, O=R
    */
    char substit3[6][2]={{'J','|'},{'L','E'},{'F','T'},{'H','I'},{'M','H'},{'O','R'}};
    testSubstitut(arr,substit3,6);
    /**
    word QETTER found HENCE, Q=L (LETTER)
    assuming Q=L QENTHER --> LEATHER    HENCE, N=A
    */
    char substit4[8][2]={{'J','|'},{'L','E'},{'F','T'},{'H','I'},{'M','H'},{'O','R'},{'Q','L'},{'N','A'}};
    testSubstitut(arr,substit4,8);
    /**
    word THIG found HENCE, G=S
    thiPD leather -> THICK LEATTER  HENCE, P=C D=K
    */
    char substit5[11][2]={{'J','|'},{'L','E'},{'F','T'},{'H','I'},{'M','H'},{'O','R'},{'Q','L'},{'N','A'},{'G','S'},{'P','C'},{'D','K'}};
    testSubstitut(arr,substit5,11);
    /**
    sooVer or later HENCE, V=N
    can Xo RithoIt -> can do without HENCE, X=D R=W I=U
    YnlW HENCE, W=Y Y=O
    */
    char substit6[17][2]={{'J','|'},{'L','E'},{'F','T'},{'H','I'},{'M','H'},{'O','R'},{'Q','L'},{'N','A'},{'G','S'},{'P','C'},{'D','K'},{'V','N'},{'X','D'},{'R','W'},{'I','U'},{'W','Y'},{'Y','O'}};
    testSubstitut(arr,substit6,17);
    /**
    B=M E=F S=P U=G |=B Z=V K=Z
    */
    char substit7[24][2]={{'J','|'},{'L','E'},{'F','T'},{'H','I'},{'M','H'},{'O','R'},{'Q','L'},{'N','A'},{'G','S'},{'P','C'},{'D','K'},{'V','N'},{'X','D'},{'R','W'},{'I','U'},{'W','Y'},{'Y','O'},{'B','M'},{'E','F'},{'S','P'},{'U','G'},{'|','B'},{'Z','V'},{'K','Z'}};
    testSubstitut(arr,substit7,24);
    return 0;
}
