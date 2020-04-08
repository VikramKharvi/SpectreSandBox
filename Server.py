#Spectre - Version 0.1
#Made by Vikram Kharvi

from flask import Flask, render_template, request
import subprocess
import os
import time
from os import path
import pandas as pd
import datetime

app = Flask(__name__)
now = datetime.datetime.now()
now = now.strftime("%Y-%m-%d-%H-%M-%S")
PMLfileName = "SpectreSandbox.pml"
CSVfileName = "SpectreSandbox.csv"


def log_debug(msg):
    if msg !="Flush":
        f = open("message.log", "a")
        f.write(msg+"\n")
        f.close()
    else:
        open("message.log", "w").close()


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/logs')
def logsDefault():
    data = ""
    f = open("message.log", "r")
    data = f.read().splitlines()
    f.close()
    return render_template('logsReport.html', data=data)


@app.route('/', methods=['POST', 'GET'])
def begin():
    if request.method == 'POST':
        if request.form['btn'] == '1':
            paths = request.form['path']
            try:
                path.exists(paths)
                f = open("path.txt", "w")
                f.write(paths)
                f.close()
            except IOError:
                log_debug("File not found")
            cmd = "Procmon.exe /BackingFile " + PMLfileName + " /Quiet /Minimized"
            log_debug("Flush")
            log_debug("Starting Procmon")
            subprocess.Popen(cmd)
            log_debug("Executed Procmon")
            time.sleep(3)
            subprocess.Popen(paths, shell=True)
            log_debug("Executed Malware")

        if request.form['btn'] == '0':
            cmd = "Procmon.exe /Terminate"
            os.system(cmd)
            log_debug("Terminated Procmon")

    return render_template('index.html')


@app.route('/logs', methods=['POST', 'GET'])
def logs():
    data = ""
    if request.method == 'POST':
        print(request.form)
        f = open("message.log", "r")
        data = f.read().splitlines()
        f.close()
    return render_template('logsReport.html', data=data)


@app.route('/analysis', methods=['POST', 'GET'])
def analysis():
    cmd = "Procmon.exe /OpenLog " + PMLfileName + " /SaveApplyFilter /SaveAs " + CSVfileName
    print(cmd)
    os.system(cmd)
    data = ''
    f = open("path.txt", "r")
    paths = f.read()
    f.close()
    fileName = os.path.basename(paths)
    df = pd.read_csv(CSVfileName, index_col=None)
    log_debug("Recieved File for analysis")
    df = df[df.Operation != "Thread Create  "]
    dfx = df[
        df['Process Name'].str.contains(fileName, regex=False) | df['Detail'].str.contains(fileName, regex=False) | df[
            'Path'].str.contains(fileName, regex=False)]
    frames = [dfx]
    for x in dfx['Path']:
        if x != '':
            subX = dfx[
                dfx['Process Name'].str.contains(x, regex=False) | dfx['Detail'].str.contains(x, regex=False) | dfx[
                    'Path'].str.contains(x, regex=False)]
            frames.append(subX)
    chained = pd.concat(frames)
    log_debug("Analysed Child Process")
    chained.to_csv('Result.csv')
    data = chained.to_numpy()
    log_debug("Completed Analysis and Converted to Array")
    return render_template("analysis.html", data=data)


if __name__ == '__main__':
    app.run(debug=True)
