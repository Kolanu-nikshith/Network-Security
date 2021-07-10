import sys



rulee = []
packett = []
def valip(temp):
    temp = temp[:-1]
    temp2 = temp.split(".")
    temp3 = temp2[3].split("/")
    temp2 = temp2[:-1]
    temp2.append(temp3[0])
    temp2.append(temp3[1])
    res = [int(ele) if ele.isdigit() else ele for ele in  temp2]
    flag1 = flag2 = flag3 = 1
    if temp == "0.0.0.0/0":
        return res,1
    if res[4]<8 or res[4]>32:
        return res,0
    for i in range(4):
        if res[i] < 0 or res[i] > 255:
            return res,0
    return res,1
            

def valport(temp):
    temp = temp[:-1].split("-")
    res = [int(ele) if ele.isdigit() else ele for ele in  temp]
    if res[0] == 0 and res[1] == 0:
        return res, 1
    elif (res[0] < 1 or res[1] > 65535) or (res[0] > res[1]) :
        return res, 0
    return res,1


def r_readandprocess(rfile):
    tpkt = 0
    validpkt = 0
    src = 0
    dest =0
    srcport = 0
    destport = 0
    prov =0
    f = open(rfile, "r")
    tempr = []
    for i in f:
        temp = i.split(" ")
        if temp[0] == "NUM:":
            tempr.append(int(temp[1]))
        elif temp[0] == "SRC" and temp[1]== "IP" and temp[2]=="ADDR:":
            res,res1 = valip(temp[3])
            if res1==1:
                src = 1
                for i in range(0,5):
                    tempr.append(res[i])

        elif temp[0] == "DEST" and temp[1] == "IP" and temp[2] == "ADDR:":
            res,res1 = valip(temp[3])
            if res1==1:
                dest = 1
                for i in range(0,5):
                    tempr.append(res[i])

        elif temp[0] == "SRC" and temp[1] == "PORT:":
            res,res1 = valport(temp[2])
            if res1==1:
                srcport = 1
                for i in range(0,2):
                    tempr.append(res[i])

        elif temp[0] == "DEST" and temp[1] == "PORT:":
            res,res1 = valport(temp[2])
            if res1==1:
                destport = 1
                for i in range(0,2):
                    tempr.append(res[i])

        elif temp[0] == "PROTOCOL:":
            temp5 = temp[1][:-1]
            if temp5 == "tcp" or temp5 == 'udp' or temp5 =='icmp':
                prov =1
            tempr.append(temp5)

        elif temp[0] == "DATA:":
            temp5 = temp[1][:-1]
            tempr.append(temp5)

        elif i[:3] == "END":
            tpkt = tpkt + 1
            if (src == 1) and (srcport == 1) and (dest == 1) and (destport == 1) and (prov==1):
                validpkt = validpkt + 1
                rulee.append(tempr)
                tempr = []
    print("Read", validpkt, " rules. ", tpkt, " valid rules stored.")


def packetread(pfile):
    f = open(pfile, "r")
    tempr = []
    for i in f:
        temp = i.split(" ")
        if temp[0] == "NUM:":
            tempnum = (int(temp[1][:-1]))
            tempr.append(tempnum)

        elif temp[0] == "SRC" and temp[1] == "IP" and temp[2] == "ADDR:":
            temp1 = temp[3][:-1]
            temp1 = temp1.split(".")
            res = [int(ele) if ele.isdigit() else ele for ele in  temp1]
            for i in range(0,4):
                tempr.append(res[i])

        elif temp[0] == "DEST" and temp[1] == "IP" and temp[2] == "ADDR:":
            temp1 = temp[3][:-1]
            temp1 = temp1.split(".")
            res = [int(ele) if ele.isdigit() else ele for ele in  temp1]
            for i in range(0,4):
                tempr.append(res[i])

        elif temp[0] == "SRC" and temp[1] == "PORT:":
            tempp = temp[2][:-1]
            tempr.append(int(tempp))
        elif temp[0] == "DEST" and temp[1] == "PORT:":
            tempp = temp[2][:-1]
            tempr.append(int(tempp))
        elif temp[0] == "PROTOCOL:":
            temppro = temp[1][:-1]
            tempr.append(temppro)
        elif temp[0] == "DATA:":
            tempdata = i[6:]
            tempr.append(tempdata)
        elif i[:3] == "END":
            packett.append(tempr)
            tempr = []


def checkpro(temp):
    if (temp == 'udp' or temp =='tcp' or temp=='icmp'):
        return 0
    else:
        return 1

def binn(ipl):
    s=""
    for ip in ipl:
        iptemp = bin(ip)[2:]
        for j in range(8 - len(iptemp)):
            iptemp = '0' + iptemp
        s = s + iptemp
    return s


def checkpack(i, pt,tt):
    s1 = ""
    s2 = ""
    ipl= []
    ptl = []
    if tt==0:
        rr = 5
        ipl = [i[1+tt], i[2+tt], i[3+tt], i[4+tt]]
    elif tt == 4:
        rr=10
        ipl = [i[1+tt+1], i[2+tt+1], i[3+tt+1], i[4+tt+1]]
    ptl  = [pt[1+tt], pt[2+tt], pt[3+tt], pt[4+tt]]    
    s1 = binn(ipl)
    s2 = binn(ptl)
    ftemp = 0 

    for j in range(i[rr]):
        if s1[j] != s2[j]:
            ftemp = 1
            continue
    return ftemp


def packetprocess():
    for pt in packett:
        found = []
        f2 = 0
        for i in rulee:
            if pt[9] < 0 or pt[9] > 65535 or pt[10] < 0 or pt[10] > 65535 or checkpro(pt[11]):
                f2 = 1
                print("Packet: ", pt[0], " is invalid.")
                break
            if i[12] == 0 and i[11] == 0:
                fflag22  = 0
            elif pt[9] < i[11] or pt[9] > i[12]:
                continue

            if i[13] == 0 and i[14] == 0:
                fflag22 = 0
            elif pt[10] < i[13] or pt[10] > i[14]:
                continue

            if not((not i[1]) and (not i[2]) and (not i[3]) and (not i[4]) and (not i[5])):
                ftemp = checkpack(i, pt,0)
                if ftemp == 1:
                    continue
            if not((not i[6]) and (not i[7]) and (not i[8]) and (not i[9]) and (not i[10])):
                ftemp = checkpack(i, pt,4)
                if ftemp == 1:
                    continue
            
            if i[16] == "*":
                fflag = 0
            if pt[12].find(i[16]) == -1:
                continue
            if pt[11] != i[15]:
                continue
            found.append(i[0])
        if f2 != 1:
            print("Packet  ", pt[0], " : Found matches =  ", len(found), " rules: ", end="")
            oo = ""
            for j in found:
                oo = oo + str(j) + ","
            print(oo[:-1])

if __name__ == '__main__':
    r_readandprocess(sys.argv[1])
    packetread(sys.argv[2])
    packetprocess()
