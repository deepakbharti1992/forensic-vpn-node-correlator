@echo off
chcp 65001 >nul
title VNC Forensic — Results
set ROOT=%~dp0
set DESKTOP=%ROOT%desktop

echo.
echo  Opening results...
echo.

:: Convert latest CSV to Excel if needed
set PYTHONIOENCODING=utf-8
python -c "
import csv, openpyxl, glob, os
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

master = r'%DESKTOP%\vnc_master_log.csv'.replace('\\\\','\\')
if not os.path.exists(master):
    print('No master log found yet — run START.bat first')
    exit()

wb = openpyxl.Workbook()
ws = wb.active
ws.title = 'VPN Master Log'

with open(master, newline='', encoding='utf-8') as f:
    rows = list(csv.reader(f))

header_fill = PatternFill('solid', fgColor='1F4E79')
header_font = Font(bold=True, color='FFFFFF', size=11)
for col, val in enumerate(rows[0], 1):
    cell = ws.cell(row=1, column=col, value=val)
    cell.fill = header_fill
    cell.font = header_font
    cell.alignment = Alignment(horizontal='center')

fill1 = PatternFill('solid', fgColor='DDEEFF')
fill2 = PatternFill('solid', fgColor='FFFFFF')
green = PatternFill('solid', fgColor='C6EFCE')
red   = PatternFill('solid', fgColor='FFC7CE')

for ri, row in enumerate(rows[1:], 2):
    rf = fill1 if ri % 2 == 0 else fill2
    for ci, val in enumerate(row, 1):
        ws.cell(row=ri, column=ci, value=val).fill = rf
    if len(row) >= 9:
        ws.cell(row=ri, column=9).fill = green if row[8].lower()=='true' else red
    if len(row) >= 10:
        ws.cell(row=ri, column=10).font = Font(bold=True)

for col in ws.columns:
    w = max((len(str(c.value or '')) for c in col), default=10)
    ws.column_dimensions[get_column_letter(col[0].column)].width = min(w+2, 35)

ws.freeze_panes = 'A2'
ws.auto_filter.ref = ws.dimensions

out = r'%DESKTOP%\vnc_master_log.xlsx'.replace('\\\\','\\')
wb.save(out)
print('Rows: ' + str(len(rows)-1))
" 2>nul

start "" "%DESKTOP%\vnc_master_log.xlsx"
