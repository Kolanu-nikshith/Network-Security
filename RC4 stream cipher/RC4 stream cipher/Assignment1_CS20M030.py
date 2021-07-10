#!/usr/bin/env python
# coding: utf-8

# # Assignment1_cs20m030 RC4 cryptanalysis

# ### Run all the cells. Main() function cell takes lot of time and outputs the stages completed

# ## I have taken four cases
# - case 1: Counter is initialised to zero once for every iteration of 40 iterations and bits toggled can be in range 1 to 2048
# - case 2: Counter is initialised to zero once for every iteration of 40 iterations and bits toggled can be in range 1500 to 
# - case 3: Counter is initialised to zero once for each bit toggled and bits toggled can be in range 1 to 2048
# - case 4: Counter is initialised to zero once for each bit toggled and bits toggled can be in range 1500 to 2048
# 2048
# 
# 
# I have taken 40 iterations for each bit toggled  and took average of them.

# In[103]:


import math
import random
import pandas as pd 
import plotly.graph_objects as go
df1 = pd.DataFrame(columns=["bits"], index = range(1,33))
df2 = pd.DataFrame(columns=["bits"], index = range(1,33))
df3 = pd.DataFrame(columns=["bits"], index = range(1,33))
df4 = pd.DataFrame(columns=["bits"], index = range(1,33))
for i in range(1,33):
    df1.loc[i,'bits'] = i
    df2.loc[i,'bits'] = i
    df3.loc[i,'bits'] = i
    df4.loc[i,'bits'] = i 


# In[104]:


def swapPos(list, i, j): 

  ##Swaps the position of two elements
    list[i], list[j] = list[j], list[i] 
    return list
 
def random_key(len): 
  ## This function generates a random binary string of given length.
  ## Here length passed to 2048, so function returns a random binary string of length 2048
    key1 = "" 
    for i in range(len): 
        key1 = key1+ str(random.randint(0, 1)) 
    return(key1) 

def toggle_key(a,j,l):
  # if j bits are to be toggled, create a list of j random numbers and
  # create a toggled key by changing only the position of bits found in the above random list
  key1 = ""                    
  c=-1
  r_list = random.sample(range(l, 2048), j)
  for i in a:
    c +=1
    if c not in r_list: 
      key1 += i
    else:
      if i is'0':
        key1 += '1'
      else:
        key1 +='0'
  return key1




def rc4(Key,b_change):
  ## Implementation of RC4 algorithm

  klen = int(len(Key)/8) 
  
  S = []
  for i in range(256):
    S.append(0)
  
  T = []
  for i in range(256):
    T.append(0)

  for i in range(256):
    S[i] = i
    temp = 0
    for j in range(8):
      if Key[(i % klen)*8 + j] is not '1':
        temp = temp + temp
      else:
        temp = temp+temp + 1
    T[i] = temp


  i = 0 
  for j in range(256):
    i = (i + S[j] + T[j]) % 256
    swapPos(S, j , i)
  
  i = 0
  j = 0
#  j = 0 
  temp1 = []
  for i in range(b_change):
    temp1.append(0)

  c = 0
  while c<b_change and i<256 :
    i = (i + 1)%256
    j = (j + S[i])% 256
    swapPos(S,i,j)
    temp1[c] = S[(S[i] + S[j])% 256]
    c = c + 1
  return temp1


def converttoBinary(x,j):
    ##We are now converting the results, we got from the above RC4 implemenatation function, to binary
  key1 = ''
  for i in x:
    key = ''
    M = bin(i)[j:]
    for m in range(j+6-len(M)):
      key += '0'
    key1 += key + M
  return key1

def caldiff(A,B):
    ## This function is used to calculate the difference between the bytes.
    ## We are performing xor operation on two bytes using this caldiff function.
    ## Calculate Xor and return 
  temp=0
  for i in range(8):
    if A[i] is B[i]:
      temp = 2*temp
    else:
      temp = 2*temp+ 1
  return temp


def calmean(counter):
    ## The counter array is passed to this function
    ## Mean of counter array is calculated and is returned back from this function
  tsum = 0
  for i in range(256):   
      tsum = tsum + counter[i]
  return tsum / 256

def sdeviation(mean,counter):
    ##The counter array and mean  are passed to this function
    ## The below function calculates standard deviation in the counter array using the mean
  tmean = 0
  for i in range(256):   #standard deviation
    tmean = tmean + (counter[i]-mean)**2
  return math.sqrt((1/256.0)*tmean)


# In[105]:


##main function to do all the cryptanalysis


if __name__ == "__main__":

  check_list = [2,4,8,16,32,64,128,256]
  for p in check_list:
    print("Calculation for Size :",p," started")    
    for j in range(1,33):
      R1 = 0
      R2 = 0
      R3 = 0
      R4 = 0
      counter1 = []                #counter1 is initialised for every bit toggled
      for i in range(256):
        counter1.append(0)
      counter2 = []                #counter2 is initialised for every bit toggled
      for i in range(256):
        counter2.append(0)
      for l in range(40):

        a=random_key(2048)         # 2048 bit random key is generated
        b=toggle_key(a,j,0)        # generates a toggled 2048 bit key               
        b1=toggle_key(a,j,1500)    # generates a toggled 2048 bit key  and bits only after 1500th bit are toggled             

        c = rc4(a,p) 
        d = rc4(b,p)
        d1 = rc4(b1,p)
        
        e = converttoBinary(c,2)
        f = converttoBinary(d,2)
        f1 = converttoBinary(d1,2)
        
        counter3 = []              #counter3 is initialised for every iteration of 40 iterations
        for i in range(256):
          counter3.append(0)
        
        counter4 = []              #counter4 is initialised for every iteration of 40 iterations
        for i in range(256):
          counter4.append(0)

        for i in range(len(e)-7):
          A=e[i:i+8]
          B=f[i:i+8]
          C=f1[i:i+8]
            
          t =caldiff(A,B)
          t1 =caldiff(A,C)
        
          
          counter1[t] = counter1[t] + 1       # outside counter toggle 1,2048
          counter2[t1] = counter2[t1] + 1     # outside counter toggle 1500,2048
          counter3[t] = counter3[t] + 1       # inside counter toggle 1,2048
          counter4[t1] = counter4[t1] + 1     # inside counter toggle 1500,2048
            
        mean4 = calmean(counter4)
        si4 = sdeviation(mean4,counter4)
        R4 = R4 + (si4 * 256 / (8*p-7))
        
        
        mean1 = calmean(counter1)
        si1 = sdeviation(mean1,counter1)
        R1 = R1 + (si1 * 256 / (8*p-7))
        
        mean2 = calmean(counter2)
        si2 = sdeviation(mean2,counter2)
        R2 = R2 + (si2 * 256 / (8*p-7))
        
        mean3 = calmean(counter3)
        si3 = sdeviation(mean3,counter3)
        R3 = R3 + (si3 * 256 / (8*p-7))
        
      df1.loc[j,str(p)] = R1/1600
      df2.loc[j,str(p)] = R2/1600
      df3.loc[j,str(p)] = R3/40
      df4.loc[j,str(p)] = R4/40
    print("Calculation for Size :",p," completed" )




# In[106]:


print("df1:",df1)
print("df2:",df2)
print("df3:",df3)
print("df4:",df4)


# # 4 graphs for 4 cases

# In[112]:


fig = go.Figure()
fig.add_trace(go.Scatter(x=df3['bits'], y=df3['2'],
                    mode='lines+markers',
                    name='2B'))
fig.add_trace(go.Scatter(x=df3['bits'], y=df3['4'],
                    mode='lines+markers',
                    name='4B'))
fig.add_trace(go.Scatter(x=df3['bits'], y=df3['8'],
                    mode='lines+markers', name='8B'))
fig.add_trace(go.Scatter(x=df3['bits'], y=df3['16'],
                    mode='lines+markers', name='16B'))
fig.add_trace(go.Scatter(x=df3['bits'], y=df3['32'],
                    mode='lines+markers', name='32B'))
fig.add_trace(go.Scatter(x=df3['bits'], y=df3['64'],
                    mode='lines+markers', name='64B'))
fig.add_trace(go.Scatter(x=df3['bits'], y=df3['128'],
                    mode='lines+markers', name='128B'))
fig.add_trace(go.Scatter(x=df3['bits'], y=df3['256'],
                    mode='lines+markers', name='256B'))


fig.update_layout(title='RC4 Cryptanalysis: Case 1: Counter is zero for every iteration and Bits toggled are in range 1 to 2048',
                   xaxis_title='Bits toggled',
                   yaxis_title='Randomness')


fig.show()


# In[113]:


fig = go.Figure()
fig.add_trace(go.Scatter(x=df4['bits'], y=df4['2'],
                    mode='lines+markers',
                    name='2B'))
fig.add_trace(go.Scatter(x=df4['bits'], y=df4['4'],
                    mode='lines+markers',
                    name='4B'))
fig.add_trace(go.Scatter(x=df4['bits'], y=df4['8'],
                    mode='lines+markers', name='8B'))
fig.add_trace(go.Scatter(x=df4['bits'], y=df4['16'],
                    mode='lines+markers', name='16B'))
fig.add_trace(go.Scatter(x=df4['bits'], y=df4['32'],
                    mode='lines+markers', name='32B'))
fig.add_trace(go.Scatter(x=df4['bits'], y=df4['64'],
                    mode='lines+markers', name='64B'))
fig.add_trace(go.Scatter(x=df4['bits'], y=df4['128'],
                    mode='lines+markers', name='128B'))
fig.add_trace(go.Scatter(x=df4['bits'], y=df4['256'],
                    mode='lines+markers', name='256B'))


fig.update_layout(title='RC4 Cryptanalysis: Case 2: Counter is zero for every iteration and Bits toggled are in range 1500 to 2048 ',
                   xaxis_title='Bits toggled',
                   yaxis_title='Randomness')


fig.show()


# In[114]:


fig = go.Figure()
fig.add_trace(go.Scatter(x=df1['bits'], y=df1['2'],
                    mode='lines+markers',
                    name='2B'))
fig.add_trace(go.Scatter(x=df1['bits'], y=df1['4'],
                    mode='lines+markers',
                    name='4B'))
fig.add_trace(go.Scatter(x=df1['bits'], y=df1['8'],
                    mode='lines+markers', name='8B'))
fig.add_trace(go.Scatter(x=df1['bits'], y=df1['16'],
                    mode='lines+markers', name='16B'))
fig.add_trace(go.Scatter(x=df1['bits'], y=df1['32'],
                    mode='lines+markers', name='32B'))
fig.add_trace(go.Scatter(x=df1['bits'], y=df1['64'],
                    mode='lines+markers', name='64B'))
fig.add_trace(go.Scatter(x=df1['bits'], y=df1['128'],
                    mode='lines+markers', name='128B'))
fig.add_trace(go.Scatter(x=df1['bits'], y=df1['256'],
                    mode='lines+markers', name='256B'))


fig.update_layout(title='RC4 Cryptanalysis: Case 3: Bits toggled are in range 1 to 2048',
                   xaxis_title='Bits toggled',
                   yaxis_title='Randomness')


fig.show()


# In[115]:


fig = go.Figure()
fig.add_trace(go.Scatter(x=df2['bits'], y=df2['2'],
                    mode='lines+markers',
                    name='2B'))
fig.add_trace(go.Scatter(x=df2['bits'], y=df2['4'],
                    mode='lines+markers',
                    name='4B'))
fig.add_trace(go.Scatter(x=df2['bits'], y=df2['8'],
                    mode='lines+markers', name='8B'))
fig.add_trace(go.Scatter(x=df2['bits'], y=df2['16'],
                    mode='lines+markers', name='16B'))
fig.add_trace(go.Scatter(x=df2['bits'], y=df2['32'],
                    mode='lines+markers', name='32B'))
fig.add_trace(go.Scatter(x=df2['bits'], y=df2['64'],
                    mode='lines+markers', name='64B'))
fig.add_trace(go.Scatter(x=df2['bits'], y=df2['128'],
                    mode='lines+markers', name='128B'))
fig.add_trace(go.Scatter(x=df2['bits'], y=df2['256'],
                    mode='lines+markers', name='256B'))


fig.update_layout(title='RC4 Cryptanalysis: RC4 Cryptanalysis: Case 4: Bits toggled are in range 1500 to 2048',
                   xaxis_title='Bits toggled',
                   yaxis_title='Randomness')


fig.show()


# In[ ]:





# In[ ]:




