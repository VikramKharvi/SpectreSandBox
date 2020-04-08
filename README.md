# SpectreSandBox
Spectre is a procmon based Point and shoot Sandbox which logs process activities of malware in realtime. 

# How to use it

1. Clone the repo to the sandbox. (Make sure you take are precautionary steps to run malware in your sandbox)
2. Download Procmon from https://docs.microsoft.com/en-us/sysinternals/downloads/procmon and place Procmon.exe under the same directory without changing its name.
3. Install Python3 (Tested on 3.6.5) from https://www.python.org/downloads/windows
4. Install flask and pandas by running "pip install flask" and "pip install pandas"
5. Run the local server by "python Server.py"
6. Drop the malware into the SandBox that you would like to analyze.
7. Open Browser enter the URL: http://127.0.0.1:5000/
8. Enter the path where you downloaded your malware on the website.
9. The Server should start running your malware. You can now interact with the malware and hit Stop when you are done. (Don't run Ransomeware as it encrypts this program)
10. Now click the Analyse button to analyze your results.
11. A CSV copy of procmon data (SandBox.csv) and analyzed data (Result.csv) of malware can be found in the same directory. (Don't open CSV while you are running the Server)
12. If you want to save this CSV file kindly copy it to the different directory as every time you analyze server overwrites it.
13. Refer to message.log if you encounter any difficulties.

Contact Information - vikram984511@gmail.com
