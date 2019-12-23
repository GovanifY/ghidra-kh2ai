import sys
import textwrap


f = open(sys.argv[1])
line = f.readline()
while line:
    if(line[0]==":"):
        words=line.split(" ",1)
        print(words[0][1:])
        code=""
        line2=f.readline()
        while(line2[0]!="}"):
            code+=line2
            line2 = f.readline()
        print(textwrap.dedent(code))
        out=open("sleigh/"+words[0][1:]+".txt", "w")
        out.write(textwrap.dedent(code))
        out.close()
    line = f.readline()
f.close()
