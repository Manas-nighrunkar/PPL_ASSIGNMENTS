from tkinter import *
from tkinter.colorchooser import askcolor
from tkinter import filedialog, simpledialog
from tkinter.filedialog import asksaveasfilename as saveAs
from PIL import Image, ImageDraw, ImageTk, ImageGrab

class Paint(object):

    DEFAULT_PEN_SIZE = 5.0
    DEFAULT_COLOR = 'black'
    
    def __init__(self):
        self.root = Tk()
        
        self.img = Image.open("unnamed.png")
        self.img = self.img.resize((50,50), Image.ANTIALIAS)
        self.brush =  ImageTk.PhotoImage(self.img)
        self.img = Image.open("pen_PNG7404.png")
        self.img = self.img.resize((50,50), Image.ANTIALIAS)
        self.pen =  ImageTk.PhotoImage(self.img)
        self.img = Image.open("color-theory.jpg")
        self.img = self.img.resize((60,60), Image.ANTIALIAS)
        self.color_pallet =  ImageTk.PhotoImage(self.img)
        self.img = Image.open("images.jpg")
        self.img = self.img.resize((60,60), Image.ANTIALIAS)
        self.eraser =  ImageTk.PhotoImage(self.img)
    
        self.pen_button = Button(self.root, text='pen', command=self.use_pen, image=self.brush)
        self.pen_button.grid(row=0, column=0)

        self.brush_button = Button(self.root, text='brush', command=self.use_brush, image=self.pen)
        self.brush_button.grid(row=0, column=1)

        self.color_button = Button(self.root, text='color', command=self.choose_color, image=self.color_pallet)
        self.color_button.grid(row=0, column=2)

        self.eraser_button = Button(self.root, text='eraser', command=self.use_eraser, image=self.eraser)
        self.eraser_button.grid(row=0, column=3)

        self.choose_size_button = Scale(self.root, from_=1, to=50, orient=HORIZONTAL)
        self.choose_size_button.grid(row=0, column=4)

        self.c = Canvas(self.root, bg='white', width=600, height=600)
        self.c.grid(row=1, columnspan=5)
        
        #creating Menu
        self.main_menu = Menu(self.root)
        self.root.config(menu=self.main_menu)
        
        #file-menu creation
        self.file_menu = Menu(self.main_menu)
        self.main_menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="New", command=self.new_)
        self.file_menu.add_command(label="Save", command=self.save_as)
        self.file_menu.add_command(label="Exit", command=self.root.destroy)
        
        self.setup()
        self.root.mainloop()

    def setup(self):
        self.old_x = None
        self.old_y = None
        self.line_width = self.choose_size_button.get()
        self.color = self.DEFAULT_COLOR
        self.eraser_on = False
        self.active_button = self.pen_button
        self.c.bind('<B1-Motion>', self.paint)
        self.c.bind('<ButtonRelease-1>', self.reset)

    def use_pen(self):
        self.activate_button(self.pen_button)

    def use_brush(self):
        self.activate_button(self.brush_button)

    def choose_color(self):
        self.eraser_on = False
        self.color = askcolor(color=self.color)[1]

    def use_eraser(self):
        self.activate_button(self.eraser_button, eraser_mode=True)

    def activate_button(self, some_button, eraser_mode=False):
        self.active_button.config(relief=RAISED)
        some_button.config(relief=SUNKEN)
        self.active_button = some_button
        self.eraser_on = eraser_mode

    def paint(self, event):
        self.line_width = self.choose_size_button.get()
        paint_color = 'white' if self.eraser_on else self.color
        if self.old_x and self.old_y:
            self.c.create_line(self.old_x, self.old_y, event.x, event.y,
                               width=self.line_width, fill=paint_color,
                               capstyle=ROUND, smooth=TRUE, splinesteps=36)
        self.old_x = event.x
        self.old_y = event.y

    def reset(self, event):
        self.old_x, self.old_y = None, None
        
    def save_as(self):
        print('\n def _snapCanvas(self):')
        canvas = self._canvas() # Get Window Coordinates of Canvas
        self.grabcanvas = ImageGrab.grab(bbox=canvas)
        #self.grabcanvas.show()
        self.path = simpledialog.askstring("", "Enter the name of file:")
        #save_path = "C:/Users/shaunak mahajan/Desktop/"
        save_path=self.path+".jpg"
        self.grabcanvas.save(save_path)
        
    def _canvas(self):
        '''print('  def _canvas(self):')
        print('self.c.winfo_rootx() = ', self.c.winfo_rootx())
        print('self.c.winfo_rooty() = ', self.c.winfo_rooty())
        print('self.c.winfo_x() =', self.c.winfo_x())
        print('self.c.winfo_y() =', self.c.winfo_y())
        print('self.c.winfo_width() =', self.c.winfo_width())
        print('self.c.winfo_height() =', self.c.winfo_height())'''
        x=self.c.winfo_rootx()+self.c.winfo_x()
        y=self.c.winfo_rooty()+self.c.winfo_y()
        x1=x+self.c.winfo_width()
        y1=y+self.c.winfo_height()
        box=(x,y,x1,y1)
        #print('box = ', box)
        return box
    
    def new_(self):
        self.root.destroy()
        Paint()


if __name__ == '__main__':
    Paint()