"use client";

import { createTheme } from "@mui/material/styles";

export const socTheme = createTheme({
  palette: {
    mode: "dark",
    primary: {
      main: "#00f0ff", // Cyan neon accent
      light: "#6dfcff",
      dark: "#00b8c4",
      contrastText: "#0a0e17",
    },
    secondary: {
      main: "#10b981", // Emerald ready
      light: "#34d399",
      dark: "#059669",
    },
    error: {
      main: "#f43f5e", // Rose
    },
    warning: {
      main: "#f59e0b", // Amber
    },
    info: {
      main: "#38bdf8", // Sky blue
    },
    success: {
      main: "#10b981",
    },
    background: {
      default: "#0a0e17",
      paper: "#111927",
    },
    text: {
      primary: "#f0f6fc",
      secondary: "#8b949e",
      disabled: "#484f58",
    },
    divider: "#1e2d42",
  },
  typography: {
    fontFamily: [
      "system-ui",
      "-apple-system",
      "BlinkMacSystemFont",
      "'Segoe UI'",
      "Roboto",
      "sans-serif",
    ].join(","),
    h1: {
      fontWeight: 800,
      letterSpacing: "-0.03em",
    },
    h2: {
      fontWeight: 700,
      letterSpacing: "-0.02em",
    },
    h3: {
      fontWeight: 600,
    },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: "none",
          fontWeight: 600,
          borderRadius: 6,
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          border: "1px solid #1e2d42",
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: "#151f32",
          border: "1px solid #1e2d42",
          borderRadius: 12,
        },
      },
    },
  },
});
