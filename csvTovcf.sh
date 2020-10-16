read file_name
if [ ! -f $file_name ]
then
echo "Enter valid file name"
exit
fi
echo "Enter the dictionary name to save the files:"
read dic_name
if [ -d $dic_name ]
then
echo "Already exist Enter another name!!"
exit
else
mkdir -p $dic_name
echo "dictionary created"
fi

OLDIFS=$IFS
IFS=','
while read first_name last_name company_name address city county state zip phone1 phone email
do
	touch $dic_name/$first_name.vcf
	echo "BEGIN:VCARD" >> $dic_name/$first_name.vcf 
	echo "VERSION:3.0" >> $dic_name/$first_name.vcf
	echo "N:$last_name;$first_name;;;" >> $dic_name/$first_name.vcf
	echo "FN:$first_name $last_name" >> $dic_name/$first_name.vcf
	echo "ORG:$company_name" >> $dic_name/$first_name.vcf
	echo "ADR;TYPE=WORK,POSTEL,PARCEL:;;$address;$city;$county;$zip;+$state" >> $dic_name/$first_name.vcf
	echo "TEL;TYPE=HOME,MSG:$phone1" >> $dic_name/$first_name.vcf
	echo "TEL;TYPE=HOME,VOICE:$phone" >> $dic_name/$first_name.vcf
	echo "EMAIL;TYPE=INTERNET:$email" >> $dic_name/$first_name.vcf
	echo "END:VCARD" >> $dic_name/$first_name.vcf
done < $file_name
IFS=$OLDIFS
