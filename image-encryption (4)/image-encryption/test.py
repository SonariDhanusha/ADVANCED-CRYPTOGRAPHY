from tkinter import *
from tkinter import ttk
from tkinter.filedialog import askopenfilename

from algorithm.image_encryption import *


def browse_file():
    init_dir = os.path.dirname(os.path.realpath(__file__))
    name = askopenfilename(initialdir=init_dir,
                           filetypes=[('All Files', '*')],
                           title="Choose a file"
                           )
    if name:
        file_name = search_file_name(name, extension=True)
        label.config(text=file_name)
        mgs_label = ttk.Label(root)
        mgs_label.place(x=350, y=250)
        encrypt_button = ttk.Button(root, text="ENCRYPTION",
                                    command=lambda: show_message(name, encrypt_button, mgs_label))
        decrypt_button = ttk.Button(root, text="DECRYPTION",
                                    command=lambda: show_message(name, decrypt_button, mgs_label))
        encrypt_button.place(x=360, y=430, height=30, width=95)
        decrypt_button.place(x=460, y=430, height=30, width=95)


def show_message(name, button, mgs_label):
    """This function is used to show the message which is returned by either Encryption or Decryption"""

    button['state'] = DISABLED  # make button state disable
    if button["text"] == "ENCRYPTION":
        mgs = image_encryption(name)
        mgs_label.config(text=mgs)

    if button["text"] == "DECRYPTION":
        mgs = image_decryption(name)
        mgs_label.config(text=mgs)


root = Tk()

app_width = 900  # window width
app_height = 500
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
# Evaluating X and Y coordinate such that, window always comes into the center.
x = int((screen_width / 2) - (app_width / 2))
y = int((screen_height / 2) - (app_height / 2))
root.geometry(f"{app_width}x{app_height}+{x}+{y}")
root.resizable(False, False)  # Window size constant

project_title = root.title("IMAGE ENCRYPTION")

canvas = Canvas(root, bg="blue", height=500, width=900)
icon = PhotoImage(file="images/th.png")  # icon for the window
root.iconphoto(False, icon)

bg = PhotoImage(file="images/back.png")
background_label = Label(root, image=bg)
background_label.place(x=0, y=0, relwidth=1, relheight=1)

img_canvas = Canvas(root, width=500, height=900)
img_canvas.pack(fill="both", expand=True)

img_canvas.create_image(0, 0, image=bg, anchor="nw")
img_canvas.create_text(450, 50, text="Image Encryption", font=("Helvetica", 50), fill="white")

browse_btn = PhotoImage(file="images/a.png")

browse_button = Button(root, borderwidth=0, background='#0000FF', foreground='#fff', text='Upload', command=browse_file)

browse_button.pack(pady=20)
browse_window = img_canvas.create_window(350, 350, anchor="nw", window=browse_button, height=50, width=200)

label = ttk.Label(root, text="No chosen file")  # Label to display the name of selected file.

label.pack()

canvas.pack()
root.mainloop()
