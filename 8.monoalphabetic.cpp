#include<stdio.h>
#include<string.h>
int main()
{
    char pt[26]={'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};
    char ct[26]={'Z','Y','X','W','V','U','T','S','R','Q','P','O','N','M','L','K','J','I','H','G','F','E','D','C','B','A'};
    char p[20],c[20],r[20];
    int i,j,ch;
    printf("\n'1' for encryption.\n'2' for decryption.\nenter your choice::");scanf("%d",&ch);
    printf("\nplease enter the text in 'CAPITALS'.");
	switch(ch)
	{
	case 1:
		{
		printf("\n enter the plain text:");
    	scanf("%s",&p);
        for(i=0;i<strlen(p);i++)
        {
	        for(j=0;j<26;j++)
            {
                if(pt[j]==p[i])
                {
                    c[i]=ct[j];
                }
            }
        }
        printf("\ncipher text is: %s",c);
		break;
		}
    case 2:
    	{
    	printf("\nenter the cipher text:");
		scanf("%s",&c);
        for(i=0;i<strlen(c);i++)
        {
        	for(j=0;j<26;j++)
            {
                if(ct[j]==c[i])
                {
                    p[i]=pt[j];
                }
            }
        }
        printf("\n plain text is: %s",p);
        break;
    	}
    }
}
