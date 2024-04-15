import numpy as np
import cv2
from flask import Flask, render_template, request , redirect, url_for , send_file, send_from_directory , Response
import os
import base64

app= Flask(__name__)
app.config["IMAGE_UPLOADS"] = r"C:\Users\hacke\OneDrive\Documents\GitHub\Steganography_webapp_using_python_flask"

UPLOAD_FOLDER = r"C:\Users\hacke\OneDrive\Documents\GitHub\Steganography_webapp_using_python_flask\static\uploads" #update the directory
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config["UP"] = r"C:\Users\hacke\OneDrive\Documents\GitHub\Steganography_webapp_using_python_flask"

def msgtobinary(msg):
    if type(msg) == str:
        result= ''.join([ format(ord(i), "08b") for i in msg ])
    
    elif type(msg) == bytes or type(msg) == np.ndarray:
        result= [ format(i, "08b") for i in msg ]
    
    elif type(msg) == int or type(msg) == np.uint8:
        result=format(msg, "08b")

    else:
        raise TypeError("Input type is not supported in this function")
    
    return result

@app.route("/deesuc.html", methods=["POST"])
def deesuc():
    if "image" in request.files:
        image = request.files["image"]
        if image.filename != "":
            image.save(os.path.join(app.config["IMAGE_UPLOADS"], image.filename))
            image.close()
            ima = image.filename
            d_data=decode_img_data(ima)
    image_path = os.path.join(app.config["IMAGE_UPLOADS"], image.filename)
    try:
                os.remove(image_path)
                print(f"Deleted {image_path}")
    except FileNotFoundError:
                print(f"{image_path} does not exist.")
     
    return render_template('deesuc.html', d_data=d_data)

@app.route("/ensuc", methods=["POST"])
def ensuc():
    if "image" in request.files:
        image = request.files["image"]
        if image.filename != "":
            image.save(os.path.join(app.config["IMAGE_UPLOADS"], image.filename))
            # Process the uploaded image (e.g., resize, analyze, etc.)
            image.close()
    user_text = request.form.get("user_text")
    print("input is ",user_text)
    # Process the user's input text (e.g., print it, analyze it, etc.)
    ima = image.filename
    encode_img_data(ima,user_text)
    with open('image.png', 'rb') as img_file:
        img_data = img_file.read()
    # Encode the image data as base64
    img_base64 = base64.b64encode(img_data).decode('utf-8')
    image_path = os.path.join(app.config["IMAGE_UPLOADS"], image.filename)
    try:
                os.remove(image_path)
                print(f"Deleted {image_path}")
    except FileNotFoundError:
                print(f"{image_path} does not exist.")

    return render_template('ensuc.html', img_base64=img_base64)

@app.route('/endcode.html')
def abc():
    return render_template("endcode.html")

@app.route('/decode.html')
def bbc():
    return render_template("decode.html")

@app.route("/desuc.html", methods=["POST"])
def desuc():
    if "image" in request.files:
        image = request.files["image"]
        if image.filename != "":
            ima = image.filename
            d_data=decode_img_data(ima)
            image.close()
    return render_template('desuc.html', d_data=d_data)


def encode_img_data(img,data):
    img=cv2.imread(img)
   # data=input("\nEnter the data to be Encoded in Image :")    
    if (len(data) == 0): 
        raise ValueError('Data entered to be encoded is empty') 
    no_of_bytes=(img.shape[0] * img.shape[1] * 3) // 8
    
   # print("\t\nMaximum bytes to encode in Image :", no_of_bytes)
    
    if(len(data)>no_of_bytes):
        raise ValueError("Insufficient bytes Error, Need Bigger Image or give Less Data !!")
    
    data +='*^*^*'    
    
    binary_data=msgtobinary(data)
    print("\n")
    #print(binary_data)
    length_data=len(binary_data)
    
   # print("\nThe Length of Binary data",length_data)
    
    index_data = 0
    
    for i in img:
        for pixel in i:
            r, g, b = msgtobinary(pixel)
            if index_data < length_data:
                pixel[0] = int(r[:-1] + binary_data[index_data], 2) 
                index_data += 1
            if index_data < length_data:
                pixel[1] = int(g[:-1] + binary_data[index_data], 2) 
                index_data += 1
            if index_data < length_data:
                pixel[2] = int(b[:-1] + binary_data[index_data], 2) 
                index_data += 1
            if index_data >= length_data:
                break
   # cv2.imwrite(nameoffile,img)
    cv2.imwrite("image.png", img)
   # print("\nEncoded the data successfully in the Image and the image is successfully saved with name ",nameoffile)



def decode_img_data(ima):
    print(ima)
    img=cv2.imread(ima)
    data_binary = ""
    for i in img:
        for pixel in i:
            r, g, b = msgtobinary(pixel) 
            data_binary += r[-1]  
            data_binary += g[-1]  
            data_binary += b[-1]  
            total_bytes = [ data_binary[i: i+8] for i in range(0, len(data_binary), 8) ]
            decoded_data = ""
            for byte in total_bytes:
                decoded_data += chr(int(byte, 2))
                if decoded_data[-5:] == "*^*^*": 
                    print("\n\nThe Encoded data which was hidden in the Image was :--  ",decoded_data[:-5])
                    return decoded_data[:-5]



def KSA(key):
    key_length = len(key)
    S=list(range(256)) 
    j=0
    for i in range(256):
        j=(j+S[i]+key[i % key_length]) % 256
        S[i],S[j]=S[j],S[i]
    return S


# In[15]:


def PRGA(S,n):
    i=0
    j=0
    key=[]
    while n>0:
        n=n-1
        i=(i+1)%256
        j=(j+S[i])%256
        S[i],S[j]=S[j],S[i]
        K=S[(S[i]+S[j])%256]
        key.append(K)
    return key


# In[16]:


def preparing_key_array(s):
    return [ord(c) for c in s]


# In[17]:


def encryption(plaintext,key):
    #print("Enter the key : ")
    key=key
    key=preparing_key_array(key)

    S=KSA(key)

    keystream=np.array(PRGA(S,len(plaintext)))
    plaintext=np.array([ord(i) for i in plaintext])

    cipher=keystream^plaintext
    ctext=''
    for c in cipher:
        ctext=ctext+chr(c)
    return ctext


# In[18]:


def decryption(ciphertext,key):
    key=key
    key=preparing_key_array(key)

    S=KSA(key)

    keystream=np.array(PRGA(S,len(ciphertext)))
    ciphertext=np.array([ord(i) for i in ciphertext])

    decoded=keystream^ciphertext
    dtext=''
    for c in decoded:
        dtext=dtext+chr(c)
    return dtext


# In[19]:


def embed(frame,user_text,key):
    data=user_text
    data=encryption(data,key)
    print("The encrypted data is : ",data)
    if (len(data) == 0): 
        raise ValueError('Data entered to be encoded is empty')

    data +='*^*^*'
    
    binary_data=msgtobinary(data)
    length_data = len(binary_data)
    
    index_data = 0
    
    for i in frame:
        for pixel in i:
            r, g, b = msgtobinary(pixel)
            if index_data < length_data:
                pixel[0] = int(r[:-1] + binary_data[index_data], 2) 
                index_data += 1
            if index_data < length_data:
                pixel[1] = int(g[:-1] + binary_data[index_data], 2) 
                index_data += 1
            if index_data < length_data:
                pixel[2] = int(b[:-1] + binary_data[index_data], 2) 
                index_data += 1
            if index_data >= length_data:
                break
        return frame


# In[20]:


def extract(frame,key):
    key=key
    print("key is ", key)
    data_binary = ""
    final_decoded_msg = ""
    
    for i in frame:
        for pixel in i:
            r, g, b = msgtobinary(pixel) 
            data_binary += r[-1]  
            data_binary += g[-1]  
            data_binary += b[-1]  
            total_bytes = [ data_binary[i: i+8] for i in range(0, len(data_binary), 8) ]
            decoded_data = ""
            for byte in total_bytes:
                decoded_data += chr(int(byte, 2))
                if decoded_data[-5:] == "*^*^*": 
                    for i in range(0,len(decoded_data)-5):
                        final_decoded_msg += decoded_data[i]
                        
                    final_decoded_msg = decryption(final_decoded_msg,key)
                    print("\n\nThe Encoded data which was hidden in the Video was :--\n",final_decoded_msg)
                    return final_decoded_msg


# In[21]:


def encode_vid_data(video,user_text,key,frame_numb):
    cap=cv2.VideoCapture("static/uploads/"+ video.filename )
    vidcap = cv2.VideoCapture("static/uploads/"+ video.filename )    
    #fourcc = cv2.VideoWriter_fourcc(*'XVID')
    fourcc = cv2.VideoWriter_fourcc(*'H264')
    frame_width = int(vidcap.get(3))
    frame_height = int(vidcap.get(4))

    size = (frame_width, frame_height)
    out = cv2.VideoWriter('static/uploads/stego_video.mp4',fourcc, 25.0, size)
    max_frame=0;
    while(cap.isOpened()):
        ret, frame = cap.read()
        if ret == False:
            break
        max_frame+=1
    cap.release()
    print("Total number of Frame in selected Video :",max_frame)
    n=frame_numb
    frame_number = 0
    while(vidcap.isOpened()):
        frame_number += 1
        ret, frame = vidcap.read()
        if ret == False:
            break
        if frame_number == n:    
            change_frame_with = embed(frame,user_text,key)
            frame_ = change_frame_with
            frame = change_frame_with
        out.write(frame)
    
    print("\nEncoded the data successfully in the video file.")
    return frame_

@app.route('/img')
def img():
    return render_template("img.html" ,steno_name="Image Steganography")
@app.route('/aud')
def aud():
    return render_template("img.html" ,steno_name="Audio Steganography")

@app.route('/vid')
def vid():
    return render_template("voi.html")

@app.route('/contact.html')
def contact():
    return render_template("contact.html")    

@app.route('/about.html')
def about():
    return render_template("about.html")  

@app.route('/index.html')
def index1():
    return render_template("index.html")  

@app.route('/vencode.html')
def vencode():
    return render_template("vencode.html")  


@app.route('/vedcode.html')
def vedcode():
    return render_template("vedcode.html")  



@app.route("/vinsuc", methods=['GET', 'POST'])
def vinsuc():
    if request.method == 'POST':
        # Handle video upload
        if 'video' in request.files:
               video=request.files['video']
               video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.filename)  
               video.save(video_path)          
        if video_path:
                user_text = request.form.get('user_text')
                key = request.form.get('key')
                frame_number = int(request.form.get('frame_number'))
                a = encode_vid_data(video,user_text,key,frame_number)
                np.save('my_array_file', a)
                delete_video(video_path)
    filename='stego_video.mp4'
    return render_template('vinsuc.html' , filename=filename )

@app.route('/static/uploads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/<filename>')
def download_files(filename):
    return send_from_directory(app.config['UP'],"my_array_file.npy" )


def delete_video(video_path):
    if video_path:
        os.remove(video_path)     



@app.route("/dinsuc", methods=['GET', 'POST'])
def dinsuc():
    if request.method == 'POST':
        # Handle video upload
        if 'video' in request.files:
               
               video=request.files['video']
               video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.filename)  
               video.save(video_path)     

        if video_path:
                user_array = request.files['user_array']
                array_path = os.path.join(app.config['UP'], user_array.filename)
                key = request.form.get('key')
                frame_number = int(request.form.get('frame_number'))
                user_array.save(array_path)
                c=user_array.filename
                a = np.load(c)   
                
                text = decode_vid_data(video,key, a ,frame_number)
                 # Delete the video file after processing
                delete_video(video_path)
                os.remove(array_path)

    return render_template('dinsuc.html' , d_data=text )


def decode_vid_data(video,key,frame_,frame_numbers):
    cap = cv2.VideoCapture("static/uploads/"+ video.filename )
    max_frame=0;
    while(cap.isOpened()):
        ret, frame = cap.read()
        if ret == False:
            break
        max_frame+=1
    print("Total number of Frame in selected Video :",max_frame)
    n=frame_numbers
    vidcap = cv2.VideoCapture("static/uploads/"+ video.filename )
    frame_number = 0
    while(vidcap.isOpened()):
        frame_number += 1
        ret, frame = vidcap.read()
        if ret == False:
            break
        if frame_number == n:
            print("caling")
            text=extract(frame_,key)
    return text
        



@app.route('/')
def index():
    return render_template("index.html")      
if __name__ == '__main__':
    with app.app_context():
        app.run(debug=True)
app.run(host="0.0.0.0",port=80)
