"use client";

import { useEffect, useRef, useState, useCallback } from "react";

export function usePoll<T>(
  fn: () => Promise<T>,
  interval = 5000,
): { data: T | null; error: string | null; loading: boolean; refetch: () => void } {
  const [data,    setData]    = useState<T | null>(null);
  const [error,   setError]   = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const run = useCallback(async () => {
    try {
      const result = await fn();
      setData(result);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [fn]);

  useEffect(() => {
    run();
    timerRef.current = setInterval(run, interval);
    return () => clearInterval(timerRef.current);
  }, [run, interval]);

  return { data, error, loading, refetch: run };
}