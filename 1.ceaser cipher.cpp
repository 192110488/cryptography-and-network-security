#include<stdio.h>
#include<string.h>
int main()
{
	char string[30];int k;
	int c;
	printf("enter the text ::");
	scanf("%s",&string);
	printf("enter the key value::");
	scanf("%d",&k);
	printf("enter '1' for encryption\'2' for decryption::");
	scanf("%d",&c);
	int l=strlen(string);
	int i;
	switch(c)
	{
	    case 1:
		{
			for(i=0; string[i] != '\0'; i++)
 		    {
	  	 	  string[i] += k;
     		}
     	printf("The cipher text is::");
   			for(i= 0; string[i]!='\0';i++)
      		{
       		      printf("%c", string[i]);
       		 }
       		 break;
   		}
    	case 2:
    	{
     		for(i=0; string[i] != '\0'; i++)
    		{
	  	  		 string[i] -= k;
     		}
     	printf("The plain text::");
   			for(i= 0; string[i]!='\0';i++)
       		{
           		  printf("%c", string[i]);
       		}
       		break;
		}

	}
}
