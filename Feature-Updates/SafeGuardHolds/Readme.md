# Safeguard Hold Database - Community Ed

I've built this database for my own use, but have published the data as well as the method I used to build it.  Thanks Adam Gross for laying the foundation:
Based on https://github.com/AdamGrossTX/FU.WhyAmIBlocked/blob/master/Get-SafeguardHoldInfo.ps1 

Basically I ran this in my environment:
#CMPIVOT Query
<#
Registry('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators\*') | where Property == 'GatedBlockId' and Value != '' and Value != 'None'
| join kind=inner (
		Registry('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\compat\appraiser\*') 
		| where Property == 'ALTERNATEDATALINK')
| join kind=inner (
		Registry('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\compat\appraiser\*') 
		| where Property == 'ALTERNATEDATAVERSION')
| project Device,GatedBlockID=Value,ALTERNATEDATALINK=Value1,ALTERNATEDATAVERSION=Value2
#>

I gathered all of the URLs (ALTERNATEDATALINK) & Versions (ALTERNATEDATAVERSION), and place them into my build script.

If you find URLs and Versions which I do not have listed, please send them to me (@gwblok on Twitter), and I'll add those and rebuild the database with anything additional that gets added.


The database is a JSON file for easy ingestion.  I have a PowerShell Sample script you can use as a template to look up the Safeguard Hold IDs easier.


Hit me up on Twitter with any questions.
