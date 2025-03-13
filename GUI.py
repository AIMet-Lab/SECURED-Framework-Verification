from tkinter import *
from tkinter import ttk
import Pmw
import webbrowser
from owlready2 import *

import os.path as os
import sys

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except:
        base_path = os.abspath(".")

    return os.join(base_path, relative_path)

logo = resource_path("logo.png")
flag = resource_path("euflag.png")
owx = resource_path("Secured.owx")

MenuItems = []

def menu():
    class SparqlQuery:
        def __init__(self):
            my_world = World()
            my_world.get_ontology(owx).load()
            self.graph = my_world.as_rdflib_graph()

        def search(self):
            query = f"""base <http://www.implementing.it/secured#>
                    
                    PREFIX sec: <http://www.implementing.it/secured#>
                    PREFIX odtmb: <http://www.grsu.by/net/OdTMBaseThreatModel#>
                    PREFIX odtmi: <http://www.grsu.by/net/OdTMIntegratedModel#>
                    
                    
                    SELECT DISTINCT ?component
                    
                    WHERE {{
                                       
                            ?component a sec:SECURED_innohub .                     
    
                    }}
                    
                    
                    ORDER BY(?component)
                    """

            resultsList = self.graph.query(query)
            for r in resultsList:
                MenuItems.append(str(r.component).replace("http://www.implementing.it/secured#",""))

    runQuery = SparqlQuery()
    runQuery.search()

menu()


class Results:
    def __init__(self, link, WID, name, subclass):
        self.link = link
        self.WID = WID
        self.name = name
        self.subclass = subclass

resultsList = []

def find(component):
    class SparqlQuery:
        def __init__(self):
            my_world = World()
            my_world.get_ontology(owx).load()
            self.graph = my_world.as_rdflib_graph()

        def search(self):
            query = f"""base <http://www.implementing.it/secured#>
                    
                    PREFIX sec: <http://www.implementing.it/secured#>
                    PREFIX odtmb: <http://www.grsu.by/net/OdTMBaseThreatModel#>
                    PREFIX odtmi: <http://www.grsu.by/net/OdTMIntegratedModel#>
                    
                    
                    SELECT ?CWE ?label ?comment (GROUP_CONCAT(DISTINCT STR(?subclass); SEPARATOR=" ;; ") as ?subclass)
                    
                    WHERE {{
                                   
                            {{  ?CWE a odtmi:CWE ;
                                    odtmb:hasTarget {component} ;
                                    rdfs:label ?label ;
                                    rdfs:comment ?comment .
                                    
                                    OPTIONAL {{ ?CWE a ?subclass .
                                                ?subclass rdfs:subClassOf odtmi:CWE }} }}
                                    
                                UNION {{
                                 
                                        ?CWE a odtmi:CWE ;
                                            sec:canFollow ?CWE0 .
                                            ?CWE0 odtmb:hasTarget {component} .
                                        ?CWE rdfs:label ?label ;
                                            rdfs:comment ?comment ;
                                            odtmb:hasDescription ?description .
                                
                                        OPTIONAL {{ ?CWE a ?subclass .
                                                    ?subclass rdfs:subClassOf odtmi:CWE }} }}
                                }}
                              
                        GROUP BY ?CWE 

                    """

            data = self.graph.query(query)
            prefix = 'http://www.implementing.it/secured#'
            for r in data:
                r = Results(r.comment, r.CWE.replace(prefix,''), r.label, r.subclass.replace(prefix,'').replace("_"," "))
                resultsList.append(r)

    runQuery = SparqlQuery()
    runQuery.search()



onto = get_ontology(owx).load()
odtmi = onto.get_namespace("http://www.grsu.by/net/OdTMIntegratedModel#")
odtmb = onto.get_namespace("http://www.grsu.by/net/OdTMBaseThreatModel#")

subclassesList = []
subclassesList.append("None")

for subclass in odtmi.CWE.subclasses():
    if str(subclass).__contains__("extension"):
        pass
    else:
        subclassesList.append(str(subclass).replace("Secured.owx.", "").replace("_", " "))



class Results2:
    def __init__(self, link, WID, name, severity):
        self.link = link
        self.WID = WID
        self.name = name
        self.severity = severity

resultsList2 = []

def find2(component):

    class SparqlQuery:
        def __init__(self):
            my_world = World()
            my_world.get_ontology(owx).load()
            self.graph = my_world.as_rdflib_graph()

        def search(self):
            query = f"""base <http://www.implementing.it/secured#>
                    
                    PREFIX sec: <http://www.implementing.it/secured#>
                    PREFIX odtmb: <http://www.grsu.by/net/OdTMBaseThreatModel#>
                    PREFIX odtmi: <http://www.grsu.by/net/OdTMIntegratedModel#>
                    
                    
                    SELECT DISTINCT ?CAPEC ?label ?comment ?severity
                    
                    WHERE {{
                                      
                        {{  ?CAPEC a odtmi:CAPEC ; 
                                odtmb:hasTarget {component} ;
                                rdfs:label ?label ;
                                rdfs:comment ?comment .
                                
                                OPTIONAL {{ ?CAPEC odtmb:hasSeverity ?severity }} }}
                             
                            UNION {{
                             
                                    ?CAPEC a odtmi:CAPEC ;
                                        sec:canFollow ?CAPEC0 .
                                        ?CAPEC0 odtmb:hasTarget {component} .
                                    ?CAPEC rdfs:label ?label ;
                                        rdfs:comment ?comment ;
                                        odtmb:hasDescription ?description .
                            
                                    OPTIONAL {{ ?CAPEC odtmb:hasSeverity ?severity }} }}
                                                               
                           }}
                        
                    GROUP BY ?CAPEC
                    ORDER BY DESC(?CAPEC)
        

                    """

            data = self.graph.query(query)
            prefix = 'http://www.implementing.it/secured#'
            for r2 in data:
                r2.comment = r2.comment[r2.comment.find("(")+1:r2.comment.find(")")]
                r2 = Results2(r2.comment, r2.CAPEC.replace(prefix, ''), r2.label, r2.severity)
                resultsList2.append(r2)

    runQuery = SparqlQuery()
    runQuery.search()



onto = get_ontology(owx).load()
odtmi = onto.get_namespace("http://www.grsu.by/net/OdTMIntegratedModel#")
odtmb = onto.get_namespace("http://www.grsu.by/net/OdTMBaseThreatModel#")

subclassesList = []
subclassesList.append("None")

for subclass in odtmi.CWE.subclasses():
    if str(subclass).__contains__("extension"):
        pass
    else:
        subclassesList.append(str(subclass).replace("Secured.owx.", "").replace("_", " "))



class Results3:
    def __init__(self, link, WID, severity, description, CPE):
        self.link = link
        self.WID = WID
        self.severity = severity
        self.description = description
        self.CPE = CPE

resultsList3 = []

def find3(component):

    class SparqlQuery:
        def __init__(self):
            my_world = World()
            my_world.get_ontology(owx).load()
            self.graph = my_world.as_rdflib_graph()

        def search(self):
            query = f"""base <http://www.implementing.it/secured#>
                    
                    PREFIX sec: <http://www.implementing.it/secured#>
                    PREFIX odtmb: <http://www.grsu.by/net/OdTMBaseThreatModel#>
                    PREFIX odtmi: <http://www.grsu.by/net/OdTMIntegratedModel#>                   
                    PREFIX schema: <https://schema.org/>
                            
                            
                    SELECT DISTINCT ?CVE ?label ?severity ?CPE (GROUP_CONCAT(DISTINCT STR(?description); SEPARATOR=" ;; ") as ?description)
                    
                    WHERE {{
                            {{        
                             ?CVE odtmb:hasTarget ?CPE .          
                             ?CPE schema:isPartOf {component} .
                    
                             ?CVE rdfs:label ?label ;
                                odtmb:hasDescription ?description .
                                      
                             OPTIONAL {{ ?CVE sec:CVSS_severity ?severity }} }}
                             
                        UNION {{
                             
                             ?CVE a odtmi:CVE ; 
                                 odtmb:hasTarget {component} ;
                                 rdfs:label ?label ;
                                 odtmb:hasDescription ?description .
                        
                                 OPTIONAL {{ ?CVE sec:CVSS_severity ?severity }} }}
                                                               
                        }}
                        
                    GROUP BY ?CVE
                    ORDER BY DESC(?CVE)
            
            """

            data = self.graph.query(query)
            prefix = 'http://www.implementing.it/secured#'
            for r3 in data:
                r3 = Results3(r3.label.replace("LINK: ", ""), r3.CVE.replace(prefix, ''), r3.severity, r3.description, r3.CPE)
                resultsList3.append(r3)


    runQuery = SparqlQuery()
    runQuery.search()


#################################################################################################################### GUI

root = Tk()
root.title("SECURED risk manager")
root.resizable(True, True)
root.configure(bg="gray")

width = root.winfo_screenwidth()
height = root.winfo_screenheight()
root.geometry("%dx%d" % (width, height))


nb = Pmw.NoteBook(root)
p1 = nb.add("Home")
p3 = nb.add("CAPEC")
p2 = nb.add("CWE")
p4 = nb.add("CVE")


p1.config(bg="white")

nb.pack(padx=5, pady=5, fill=BOTH, expand=1)


################################################################################################################ Sheet 1


imgSec = PhotoImage(file=logo)
Label(p1, image=imgSec, borderwidth=0).place(relx=.5, rely=.45, anchor="center")

imgEu = PhotoImage(file=flag)
Label(p1, image=imgEu, borderwidth=0).place(relx=.4, rely=.9, anchor="center")

funding = """This project has received funding from the
 European Union’s Horizon Europe research
   and innovation programme under Grant
    Agreement No 101095717."""

Label(p1, text=funding, bg="white").place(relx=.55, rely=.9, anchor="center")


frmTop = Frame(p1, bg="gray")
frmTop.pack(side=TOP)

style = ttk.Style()

style.map("TCombobox", foreground=[("readonly", "gray")])
style.map("TCombobox", fieldbackground=[("readonly", "white")])
style.map("TCombobox", selectbackground=[("readonly", "white")])
style.map("TCombobox", selectforeground=[("readonly", "black")])

MenuBox = ttk.Combobox(frmTop, values=MenuItems, state="readonly", width=45)


################################################################################################################ Sheet 3


### Function to find info about retrieved threats from CWE

titleVar = StringVar()
nameVar = StringVar()

iTextVar = StringVar()
sTextVar = StringVar()
dTextVar = StringVar()
mTextVar = StringVar()
CVETextVar = StringVar()
CAPECTextVar = StringVar()

iSet = set()
sSet = set()
dSet = set()
mSet = set()
CVESet = set()
CAPECSet = set()
nameSet = set()

def clearSets():
    iSet.clear()
    sSet.clear()
    dSet.clear()
    mSet.clear()
    CVESet.clear()
    CAPECSet.clear()
    nameSet.clear()

def findInfo(CWE):

    class SparqlQuery:
        def __init__(self):
            my_world = World()
            my_world.get_ontology(owx).load()
            self.graph = my_world.as_rdflib_graph()

        titleVar.set("")
        nameVar.set("Name:")
        iTextVar.set("Impact:")
        sTextVar.set("Scope:")
        dTextVar.set("Description:")
        mTextVar.set("Mitigation:")
        CVETextVar.set("refToCVE:")
        CAPECTextVar.set("isRefToCAPEC:")

        def search(self):
            query = f"""base <http://www.implementing.it/secured#>
                    
                    PREFIX sec: <http://www.implementing.it/secured#>
                    PREFIX odtmb: <http://www.grsu.by/net/OdTMBaseThreatModel#>
                    PREFIX odtmi: <http://www.grsu.by/net/OdTMIntegratedModel#>
                    
                    
                    SELECT ?label ?impact ?scope ?description ?mitigation ?CVE ?CAPEC
                    
                    WHERE {{
                            {CWE} rdfs:label ?label .
                            
                            OPTIONAL {{ {CWE} sec:impact ?impact }}
                            OPTIONAL {{ {CWE} sec:scope ?scope }}
                            OPTIONAL {{ {CWE} odtmb:hasDescription ?description }}
                            OPTIONAL {{ {CWE} sec:mitigation ?mitigation }}
                            OPTIONAL {{ {CWE} odtmb:refToCVE ?CVE }}
                            OPTIONAL {{ {CWE} odtmb:isRefToCAPEC ?CAPEC }}
                                
                            }}
                    
                    """

            data = self.graph.query(query)

            for i in data:
                iSet.add(str(i.impact))
                sSet.add(str(i.scope))
                dSet.add(str(i.description))
                mSet.add(str(i.mitigation))
                nameSet.add(str(i.label))

                CVESet.add(str(i.CVE).replace("http://www.implementing.it/secured#",""))
                CAPECSet.add(str(i.CAPEC).replace("http://www.implementing.it/secured#",""))


            titleVar.set(CWE.lstrip("sec:"))
            nameVar.set(f"{list(nameSet)}")

            iTextVar.set(f"Impact: {list(iSet)}")
            sTextVar.set(f"Scope: {list(sSet)}")
            dTextVar.set(f"Description: {list(dSet)}")
            mTextVar.set(f"Mitigation: {list(mSet)}")
            CVETextVar.set(f"refToCVE: {list(CVESet)}")
            CAPECTextVar.set(f"isRefToCAPEC: {list(CAPECSet)}")

            clearSets()

    runQuery = SparqlQuery()
    runQuery.search()


### Function to find info about retrieved threats from CAPEC

title2Var = StringVar()
name2Var = StringVar()

i2TextVar = StringVar()
s2TextVar = StringVar()
l2TextVar = StringVar()
d2TextVar = StringVar()
m2TextVar = StringVar()
CWEVar = StringVar()

name2Set = set()
i2Set = set()
s2Set = set()
l2Set = set()
d2Set = set()
m2Set = set()
CWESet = set()

def clearSets2():
    name2Set.clear()
    i2Set.clear()
    s2Set.clear()
    l2Set.clear()
    d2Set.clear()
    m2Set.clear()
    CWESet.clear()

def findInfo2(CAPEC):
    class SparqlQuery:
        def __init__(self):
            my_world = World()
            my_world.get_ontology(owx).load()
            self.graph = my_world.as_rdflib_graph()

        title2Var.set("")
        name2Var.set("Name:")
        i2TextVar.set("Impact:")
        s2TextVar.set("Scope:")
        l2TextVar.set("Likelihood:")
        d2TextVar.set("Description:")
        m2TextVar.set("Mitigation:")
        CWEVar.set("refToCWE:")

        def search(self):
            query = f"""base <http://www.implementing.it/secured#>
                    
                    PREFIX sec: <http://www.implementing.it/secured#>
                    PREFIX odtmb: <http://www.grsu.by/net/OdTMBaseThreatModel#>
                    PREFIX odtmi: <http://www.grsu.by/net/OdTMIntegratedModel#>
                    
                    
                    SELECT DISTINCT ?label ?impact ?scope ?likelihood ?description ?mitigation ?CWE
                    
                    WHERE {{
                            {CAPEC} rdfs:label ?label .
                            
                            OPTIONAL {{ {CAPEC} sec:impact ?impact }}
                            OPTIONAL {{ {CAPEC} sec:scope ?scope }}
                            OPTIONAL {{ {CAPEC} odtmb:hasDescription ?description }}
                            OPTIONAL {{ {CAPEC} sec:mitigation ?mitigation }}
                            OPTIONAL {{ {CAPEC} sec:likelihood ?likelihood }}
                            OPTIONAL {{ {CAPEC} sec:likelihood ?likelihood }}
                            OPTIONAL {{ {CAPEC} odtmb:refToCWE ?CWE }}
                             
                            }}
                    
                    """

            data = self.graph.query(query)

            for i in data:
                name2Set.add(str(i.label))
                i2Set.add(str(i.impact))
                s2Set.add(str(i.scope))
                l2Set.add(str(i.likelihood))
                d2Set.add(str(i.description))
                m2Set.add(str(i.mitigation))
                CWESet.add(str(i.CWE).replace("http://www.implementing.it/secured#",""))

            title2Var.set(CAPEC.lstrip("sec:"))
            name2Var.set(f"Name: {list(name2Set)}")

            i2TextVar.set(f"Impact: {list(i2Set)}")
            s2TextVar.set(f"Scope: {list(s2Set)}")
            l2TextVar.set(f"Likelihood: {list(l2Set)}")
            d2TextVar.set(f"Description: {list(d2Set)}")
            m2TextVar.set(f"Mitigation: {list(m2Set)}")
            CWEVar.set(f"refToCWE: {list(CWESet)}")

            clearSets2()

    runQuery = SparqlQuery()
    runQuery.search()



### Function to find info about retrieved threats from CVE

title3Var = StringVar()
d3TextVar = StringVar()
CWE2Var = StringVar()

d3Set = set()
CWE2Set = set()

def clearSets3():
    d3Set.clear()
    CWE2Set.clear()

def findInfo3(CVE):
    class SparqlQuery:
        def __init__(self):
            my_world = World()
            my_world.get_ontology(owx).load()
            self.graph = my_world.as_rdflib_graph()

        title3Var.set("")
        d3TextVar.set("Description:")
        CWE2Var.set("isRefToCWE:")


        def search(self):
            query = f"""base <http://www.implementing.it/secured#>
                    
                    PREFIX sec: <http://www.implementing.it/secured#>
                    PREFIX odtmb: <http://www.grsu.by/net/OdTMBaseThreatModel#>
                    PREFIX odtmi: <http://www.grsu.by/net/OdTMIntegratedModel#>
                    
                    
                    SELECT DISTINCT ?description ?CWE
                    
                    WHERE {{
                            {CVE} odtmb:hasDescription ?description .
                            
                            OPTIONAL {{ {CVE} sec:isRefToCWE ?CWE }} 
                               
                            }}
                    
                    """

            data = self.graph.query(query)

            for i in data:
                d3Set.add(str(i.description))
                CWE2Set.add(str(i.CWE).replace("http://www.implementing.it/secured#",""))


            title3Var.set(CVE.lstrip("sec:"))
            d3TextVar.set(f"Description: {list(d3Set)}")
            CWE2Var.set(f"isRefToCWE: {list(CWE2Set)}")

            clearSets3()

    runQuery = SparqlQuery()
    runQuery.search()


### Function to select and show info on CWEs

def selector(Selected):
    global scrolledfr
    scrolledfr.destroy()
    scrolledfr = Pmw.ScrolledFrame(p2)
    scrolledfr.pack(side=LEFT, fill=BOTH, expand=YES, padx=2, pady=5)
    frame1 = scrolledfr.interior()

    global scrolledfr2
    scrolledfr2.destroy()
    scrolledfr2 = Pmw.ScrolledFrame(p2)
    scrolledfr2.pack(side=LEFT, fill=BOTH, expand=YES, padx=2, pady=5)
    frame2 = scrolledfr2.interior()

    ### Labels which show info on the right

    Label(frame2, textvariable=titleVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 30)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame2, textvariable=nameVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 15)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame2, textvariable=iTextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 10)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame2, textvariable=sTextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 10)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame2, textvariable=dTextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("arial", 12)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame2, textvariable=mTextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("arial", 12)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame2, textvariable=CAPECTextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("arial", 12)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame2, textvariable=CVETextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("arial", 12)).pack(
        side=TOP, fill=X, expand=YES)


    ### Component and Filter selectors

    resultsList.clear()
    Selected = MenuBox.get()
    find(f"sec:{Selected}")
    FilterBox.configure(values=subclassesList)
    SelectedFilter = FilterBox.get()

    global n
    n = 0

    ### Function to create buttons and icons on the left

    def createButtons():
        global n
        n += 1

        Button(frame1, anchor="w", text=r.WID, activebackground="gray", bg="white", padx=2, pady=0, width=8,
                    command=lambda x=r.link: webbrowser.open(x)).grid(row=n, column=0, sticky="w")

        if len(r.name.split()) > 12:
            name = " ".join(r.name.split()[:12])+"..."
        else:
            name = r.name

        Button(frame1, anchor="w", text=name, activebackground="gray", bg="white", padx=2, pady=0, width=88,
                    command=lambda x=f"sec:{r.WID}": findInfo(x)).grid(row=n, column=1, sticky="w")


        iconsLabel1 = Label(frame1, bg="white", text="CISQ", fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel1.grid(row=n, column=2, sticky="ew")
        iconsLabel2 = Label(frame1, bg="white", text="HW", fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel2.grid(row=n, column=3, sticky="ew")
        iconsLabel3 = Label(frame1, bg="white", text="SW", fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel3.grid(row=n, column=4, sticky="ew")
        Label(frame1, bg="white", text=" ", fg="white", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3).grid(row=n, column=5, sticky="ew")


        if r.subclass.__contains__("CISQ"):
            iconsLabel1.configure(fg="light slate blue")
        if r.subclass.__contains__("HW"):
            iconsLabel2.configure(fg="purple")
        if r.subclass.__contains__("SW"):
            iconsLabel3.configure(fg="blue")


    ### Loop to create buttons according to filters

    for r in resultsList:
        if SelectedFilter == "Filter by TOP threats list" or SelectedFilter == "None":
            createButtons()
        elif r.subclass.__contains__(SelectedFilter):
            createButtons()


    CWEcounter.set(f"Results from CWE: {n}")


################################################################################################################ Sheet 2

### Function to select and show info on CAPECs

    global scrolledfr3
    scrolledfr3.destroy()
    scrolledfr3 = Pmw.ScrolledFrame(p3)
    scrolledfr3.pack(side=LEFT, fill=BOTH, expand=YES, padx=2, pady=5)
    frame3 = scrolledfr3.interior()

    global scrolledfr4
    scrolledfr4.destroy()
    scrolledfr4 = Pmw.ScrolledFrame(p3)
    scrolledfr4.pack(side=LEFT, fill=BOTH, expand=YES, padx=2, pady=5)
    frame4 = scrolledfr4.interior()

    ### Labels which show info on the right

    Label(frame4, textvariable=title2Var, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 30)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame4, textvariable=name2Var, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 15)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame4, textvariable=i2TextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 10)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame4, textvariable=s2TextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 10)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame4, textvariable=l2TextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 10)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame4, textvariable=d2TextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("arial", 12)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame4, textvariable=m2TextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("arial", 12)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame4, textvariable=CWEVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("arial", 12)).pack(
        side=TOP, fill=X, expand=YES)

    ### Component and Filter selectors

    resultsList2.clear()
    find2(f"sec:{Selected}")

    filters2 = ("None", "Very High", "High", "Medium")
    FilterBox2.configure(values=filters2)
    SelectedFilter2 = FilterBox2.get()

    global n2
    n2 = 0

    ### Function to create buttons and icons on the left

    def createButtons2():
        global n2
        n2 += 1
        Button(frame3, anchor="w", text=r2.WID, activebackground="gray", bg="white", padx=2, pady=0, width=9,
                    command=lambda x=r2.link: webbrowser.open(x)).grid(row=n2, column=0, sticky="w")

        Button(frame3, anchor="w", text=r2.name, activebackground="gray", bg="white", padx=2, pady=0, width=92,
                    command=lambda x=f"sec:{r2.WID}": findInfo2(x)).grid(row=n2, column=1, sticky="w")


        iconsLabel4 = Label(frame3, bg="white", text="VH", fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel4.grid(row=n2, column=2, sticky="ew")
        iconsLabel5 = Label(frame3, bg="white", text="H", fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel5.grid(row=n2, column=3, sticky="ew")
        iconsLabel6 = Label(frame3, bg="white", text="M", fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel6.grid(row=n2, column=4, sticky="ew")
        Label(frame3, bg="white", text=" ", fg="white", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3).grid(row=n2, column=5, sticky="ew")



        if str(r2.severity) == "Very High":
            iconsLabel4.configure(fg="purple")
        if str(r2.severity) == "High":
            iconsLabel5.configure(fg="red")
        if str(r2.severity) == "Medium":
            iconsLabel6.configure(fg="orange")


    ### Loop to create buttons according to filters

    for r2 in resultsList2:
        if SelectedFilter2 == "Filter by typical severity" or SelectedFilter2 == "None":
            createButtons2()
        elif str(r2.severity) == SelectedFilter2:
            createButtons2()


    CAPECcounter.set(f"\nResults from CAPEC: {n2}")


################################################################################################################ Sheet 4

### Function to select and show info on CVEs

    global scrolledfr5
    scrolledfr5.destroy()
    scrolledfr5 = Pmw.ScrolledFrame(p4)
    scrolledfr5.pack(side=LEFT, fill=BOTH, expand=YES, padx=2, pady=5)
    frame5 = scrolledfr5.interior()

    global scrolledfr6
    scrolledfr6.destroy()
    scrolledfr6 = Pmw.ScrolledFrame(p4)
    scrolledfr6.pack(side=LEFT, fill=BOTH, expand=YES, padx=2, pady=5)
    frame6 = scrolledfr6.interior()

    ### Labels which show info on the right

    Label(frame6, textvariable=title3Var, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("Helvetica", 30)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame6, textvariable=d3TextVar, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("arial", 12)).pack(
        side=TOP, fill=X, expand=YES)
    Label(frame6, textvariable=CWE2Var, justify=LEFT, anchor="w", wraplength=800, padx=50, pady=10, font=("arial", 12)).pack(
        side=TOP, fill=X, expand=YES)

    ### Component and Filter selectors

    resultsList3.clear()
    find3(f"sec:{Selected}")

    filters3 = ("None", "CPE-NVD", "Critical", "High", "Medium")
    FilterBox3.configure(values=filters3)
    SelectedFilter3 = FilterBox3.get()

    global n3
    n3 = 0

    ### Function to create buttons and icons on the left

    def createButtons3():
        global n3
        n3 += 1


        name = " ".join(r3.description.split()[:10])+"..."

        Button(frame5, anchor="w", text=r3.WID, activebackground="gray", bg="white", padx=2, pady=0, width=15,
                    command=lambda x=r3.link: webbrowser.open(x)).grid(row=n3, column=0, sticky="w")

        Button(frame5, anchor="w", text=name, activebackground="gray", bg="white", padx=2, pady=0, width=78,
                    command=lambda x=f"sec:{r3.WID}": findInfo3(x)).grid(row=n3, column=1, sticky="w")


        if r3.CPE:
            source = "CPE-NVD "
        else:
            source = "Keyword "

        iconsLabel7 = Label(frame5, bg="white", text=source, fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel7.grid(row=n3, column=2, sticky="ew")
        iconsLabel8 = Label(frame5, bg="white", text="C", fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel8.grid(row=n3, column=3, sticky="ew")
        iconsLabel9 = Label(frame5, bg="white", text="H", fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel9.grid(row=n3, column=4, sticky="ew")
        iconsLabel10 = Label(frame5, bg="white",text="M", fg="light gray", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3)
        iconsLabel10.grid(row=n3, column=5, sticky="ew")
        Label(frame5, bg="white", text="  ", fg="white", font=("arial", 10, "bold"), relief=RAISED, pady=3, padx=3).grid(row=n3, column=6, sticky="ew")

        if str(r3.severity).title() == "Critical":
                iconsLabel8.configure(fg="purple")
        if str(r3.severity).title() == "High":
            iconsLabel9.configure(fg="red")
        if str(r3.severity).title() == "Medium":
            iconsLabel10.configure(fg="orange")

    ### Loop to create buttons according to filters

    for r3 in resultsList3:
        if SelectedFilter3 == "Filter by CVSS severity" or SelectedFilter3 == "None":
            createButtons3()
        if SelectedFilter3 == "CPE-NVD" and r3.CPE:
            createButtons3()
        elif SelectedFilter3 == str(r3.severity).title():
            createButtons3()


    CVEcounter.set(f"Results from CVE: {n3}")

################################################################################################################ Packing

CAPECcounter = StringVar()
Label(p1, textvariable=CAPECcounter, bg="white", fg="red").pack(pady=5)

CWEcounter = StringVar()
Label(p1, textvariable=CWEcounter, bg="white", fg="red").pack(pady=5)

CVEcounter = StringVar()
Label(p1, textvariable=CVEcounter, bg="white", fg="red").pack(pady=5)

MenuBox.bind("<<ComboboxSelected>>", selector)
MenuBox.set("Select a SECURED component")
MenuBox.pack(side=LEFT)

frmTop2 = Frame(p2, bg="gray")
frmTop2.pack(side=TOP)

frmTop3 = Frame(p3, bg="gray")
frmTop3.pack(side=TOP)

frmTop4 = Frame(p4, bg="gray")
frmTop4.pack(side=TOP)

FilterBox = ttk.Combobox(frmTop2, state="readonly", width=45)
FilterBox.bind("<<ComboboxSelected>>", selector)
FilterBox.set("Filter by TOP threats list")
FilterBox.pack(side=LEFT)

FilterBox2 = ttk.Combobox(frmTop3, state="readonly", width=45)
FilterBox2.bind("<<ComboboxSelected>>", selector)
FilterBox2.set("Filter by typical severity")
FilterBox2.pack(side=LEFT)

FilterBox3 = ttk.Combobox(frmTop4, state="readonly", width=45)
FilterBox3.bind("<<ComboboxSelected>>", selector)
FilterBox3.set("Filter by CVSS severity")
FilterBox3.pack(side=LEFT)

scrolledfr = Pmw.ScrolledFrame(p2)
scrolledfr2 = Pmw.ScrolledFrame(p2)

scrolledfr3 = Pmw.ScrolledFrame(p3)
scrolledfr4 = Pmw.ScrolledFrame(p3)

scrolledfr5 = Pmw.ScrolledFrame(p4)
scrolledfr6 = Pmw.ScrolledFrame(p4)

root.mainloop()
