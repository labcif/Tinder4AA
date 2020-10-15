# LabCIF - Tinder for Android Analyzer 
#### Module for Autopsy Forensic Browser
## Getting Started

Tinder application extension for Android Analyzer running on Autopsy

## Artifacts
* Tinder messages
* Tinder contacts

## Prerequisites

* [Autopsy](https://www.sleuthkit.org/autopsy/)


### Running from Autopsy

Since the Android Analyzer is an internal module of Autopsy, it will not appear in the directory of external modules python_modules. The internal modules can be found in the sub-directory:
*autopsy/InternalPythonModules* where the contents of Autopsy are present. By default, in the Windows 10 operating system, the directory is:
*C:/ProgramFiles/Autopsy-4.15.0/autopsy/InternalPythonModules*.


1. Move the *tinder.py* file to the Internal Python Modules folder.
2. Add Tinder dependency on *module.py* file.

```python 
import tinder
```

To add the Tinder dependency in the module.py file, add the line “*import tinder*” in the imports section.

3. Add Tinder analyzer to the list of analysers already in *module.py*.

```python
analyzers = [contact.ContactAnalyzer(),
calllog.CallLogAnalyzer(),
textmessage.TextMessageAnalyzer(),
tangomessage.TangoMessageAnalyzer(),
wwfmessage.WWFMessageAnalyzer(),
googlemaplocation.GoogleMapLocationAnalyzer(),
browserlocation.BrowserLocationAnalyzer(),
cachelocation.CacheLocationAnalyzer(),
imo.IMOAnalyzer(),xender.XenderAnalyzer(), zapya.ZapyaAnalyzer(), shareit.ShareItAnalyzer(), line.LineAnalyzer(), whatsapp.WhatsAppAnalyzer(), textnow.TextNowAnalyzer(), skype.SkypeAnalyzer(),
viber.ViberAnalyzer(),
fbmessenger.FBMessengerAnalyzer(), sbrowser.SBrowserAnalyzer(), operabrowser.OperaAnalyzer(), oruxmaps.OruxMapsAnalyzer(), tinder.TinderAnalyzer(),
installedapps.InstalledApplicationsAnalyzer()]
```
       


## Authors

* **José Francisco** - [GitHub](https://github.com/98jfran)
* **Ruben Nogueira** - [GitHub](https://github.com/rubnogueira)
* **Patrício Domingues** - [GitHub](https://github.com/PatricioDomingues)
* **Miguel Frade** - [GitHub](https://github.com/mfrade)

Project developed as final project for Computer Engineering course in Escola Superior de Tecnologia e Gestão de Leiria.

## Environments Tested

* Autopsy 4.14
* Autopsy 4.15
* Autopsy 4.16

## License

GNU General Public License v3.0

## Notes

* Made with ❤ in Leiria, Portugal