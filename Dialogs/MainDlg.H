#ifndef _MAINDLG_H
#define _MAINDLG_H
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//---------------------(Constant Definitions)
#define MAINDIALOG_MENU_ABOUT 1000

#define COL_DATE_POS	0
#define COL_TIME_POS	1
#define COL_PROTO		2
#define COL_S_IP_POS	3
#define COL_D_IP_POS	4
#define COL_SPORT_POS	5
#define COL_DPORT_POS	6
#define COL_TEXT_POS	7
#define COL_SIZE_POS	8

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//---------------------(Variable Declarations)
extern HWND hMainDialog;
extern HWND hItemList;
extern HWND hStatusBar;
extern BINARY_DATA *BinDataPointer;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//---------------------(Function Prototypes)
INT_PTR CALLBACK MainDialog(HWND hHwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

bool IsPaused(void);
void Pause(void);
void Resume(void);
void Stop(void);
void Start(void);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
