import { Component, type ReactNode } from "react";
import { ErrorState } from "@redjohn/ui";

interface Props {
  children: ReactNode;
}
interface State {
  error: Error | null;
}

/**
 * Last-resort render boundary. The renderer applies events from a separately
 * versioned engine process, so a single unexpected value (an unknown enum, a
 * missing optional field) must not white-screen the entire app. Scope this
 * around the page area and give it a `key` tied to the current view so
 * navigating away clears the error without a full reload.
 */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error): void {
    console.error("Renderer error boundary caught:", error);
  }

  override render(): ReactNode {
    if (this.state.error) {
      return (
        <div className="flex min-h-0 flex-1 items-center justify-center p-6">
          <ErrorState
            title="This view hit an unexpected error"
            detail={this.state.error.message}
            onRetry={() => window.location.reload()}
          />
        </div>
      );
    }
    return this.props.children;
  }
}
