import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getGetDashboardSummaryQueryKey, getGetRecentEventsQueryKey, getGetAlertsQueryKey } from '@workspace/api-client-react';
import { useToast } from './use-toast';

export function useRealtimeSoc() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let unmounted = false;
    let reconnectTimeout: any = null;

    function connect() {
      if (unmounted) return;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (unmounted) return;
          setConnected(true);
          console.log('[SOC Stream] Connected to real-time WebSocket');
        };

        ws.onmessage = (event) => {
          if (unmounted) return;
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'EVENT_NEW' || data.type === 'DASHBOARD_UPDATE') {
              queryClient.invalidateQueries({ queryKey: getGetDashboardSummaryQueryKey() });
              queryClient.invalidateQueries({ queryKey: getGetRecentEventsQueryKey({ limit: 8 }) });
              queryClient.invalidateQueries({ queryKey: ['getRecentEvents'] });
            } else if (data.type === 'ALERT_NEW') {
              queryClient.invalidateQueries({ queryKey: getGetDashboardSummaryQueryKey() });
              queryClient.invalidateQueries({ queryKey: getGetAlertsQueryKey() });

              const alert = data.payload;
              if (alert?.severity === 'HIGH' || alert?.severity === 'CRITICAL') {
                toast({
                  title: `🚨 ${alert.severity} Alert: ${alert.title}`,
                  description: alert.description || 'New high-risk security signal detected.',
                  variant: 'destructive',
                });
              }
            } else if (data.type === 'INCIDENT_UPDATE') {
              queryClient.invalidateQueries({ queryKey: getGetDashboardSummaryQueryKey() });
              queryClient.invalidateQueries({ queryKey: getGetAlertsQueryKey() });
              toast({
                title: `🔥 Correlated Incident: ${data.payload.title}`,
                description: data.payload.summary || 'Multi-vector threat campaign correlated.',
                variant: 'destructive',
              });
            }
          } catch (e) {
            console.error('[SOC Stream] Error parsing WS message', e);
          }
        };

        ws.onclose = () => {
          if (unmounted) return;
          setConnected(false);
          reconnectTimeout = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch (err) {
        console.error('[SOC Stream] Connection failed', err);
        reconnectTimeout = setTimeout(connect, 5000);
      }
    }

    connect();

    return () => {
      unmounted = true;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (wsRef.current) wsRef.current.close();
    };
  }, [queryClient, toast]);

  return { connected };
}
