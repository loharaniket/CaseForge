"use client";

import { createTheme } from "@mui/material/styles";

export const socTheme = createTheme({
  palette: {
    mode: "light",
    primary: {
      main: "#1F4E79",
      light: "#EAF2F8",
      dark: "#173A5C",
      contrastText: "#FFFFFF",
    },
    secondary: {
      main: "#2B6CB0",
      light: "#EAF3FB",
      dark: "#1A4971",
      contrastText: "#FFFFFF",
    },
    error: {
      main: "#C53030",
      light: "#FDECEC",
      dark: "#9B1C1C",
      contrastText: "#FFFFFF",
    },
    warning: {
      main: "#B7791F",
      light: "#FFF7E6",
      dark: "#975A16",
      contrastText: "#FFFFFF",
    },
    info: {
      main: "#2B6CB0",
      light: "#EAF3FB",
      dark: "#1A4971",
      contrastText: "#FFFFFF",
    },
    success: {
      main: "#237A57",
      light: "#E8F5EF",
      dark: "#18533B",
      contrastText: "#FFFFFF",
    },
    background: {
      default: "#F5F7FA",
      paper: "#FFFFFF",
    },
    text: {
      primary: "#17212B",
      secondary: "#52606D",
      disabled: "#A0AAB4",
    },
    divider: "#D9E0E7",
  },
  typography: {
    fontFamily: [
      "Inter",
      "system-ui",
      "-apple-system",
      "BlinkMacSystemFont",
      "'Segoe UI'",
      "sans-serif",
    ].join(","),
    h1: {
      fontSize: "24px",
      fontWeight: 700,
      color: "#17212B",
    },
    h2: {
      fontSize: "22px",
      fontWeight: 650,
      color: "#17212B",
    },
    h3: {
      fontSize: "16px",
      fontWeight: 650,
      color: "#17212B",
    },
    h4: {
      fontSize: "14px",
      fontWeight: 650,
      color: "#17212B",
    },
    body1: {
      fontSize: "14px",
      fontWeight: 400,
      color: "#17212B",
    },
    body2: {
      fontSize: "13px",
      fontWeight: 400,
      color: "#52606D",
    },
    subtitle1: {
      fontSize: "14px",
      fontWeight: 650,
    },
    subtitle2: {
      fontSize: "13px",
      fontWeight: 650,
    },
    caption: {
      fontSize: "11px",
      color: "#7B8794",
    },
  },
  shape: {
    borderRadius: 6,
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: "none",
          fontWeight: 600,
          borderRadius: 6,
          height: 36,
          padding: "0 14px",
          boxShadow: "none",
          fontSize: "13px",
          "&:hover": {
            boxShadow: "none",
          },
        },
        containedPrimary: {
          backgroundColor: "#1F4E79",
          color: "#FFFFFF",
          "&:hover": {
            backgroundColor: "#173A5C",
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          border: "1px solid #D9E0E7",
          boxShadow: "0 1px 3px rgba(16,24,40,0.06)",
        },
        elevation0: {
          boxShadow: "none",
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: "#FFFFFF",
          border: "1px solid #D9E0E7",
          borderRadius: 8,
          boxShadow: "0 1px 3px rgba(16,24,40,0.06)",
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderBottom: "1px solid #E5EAF0",
          fontSize: "13px",
          color: "#17212B",
        },
        head: {
          backgroundColor: "#F8FAFC",
          color: "#52606D",
          fontWeight: 650,
          fontSize: "12px",
        },
      },
    },
    MuiTableRow: {
      styleOverrides: {
        root: {
          height: 48,
          "&:hover": {
            backgroundColor: "#F8FAFC",
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          height: 24,
          borderRadius: 12,
          fontSize: "11px",
          fontWeight: 650,
        },
      },
    },
  },
});
