import React from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@xterm/xterm/css/xterm.css";
import "./index.css";
import { App } from "./App";
import { EngineProvider } from "./lib/engine";
import { useUiStore } from "./store/ui";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5_000,
    },
  },
});

void useUiStore.getState().hydrate();

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <EngineProvider>
        <App />
      </EngineProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
