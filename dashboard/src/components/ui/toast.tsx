import React, { useState, useEffect } from 'react';
import { CheckCircle, AlertTriangle, Info, X } from 'lucide-react';

export interface Toast {
  id: string;
  title: string;
  description?: string;
  type: 'success' | 'error' | 'warning' | 'info';
  duration?: number;
}

interface ToastProviderProps {
  children: React.ReactNode;
}

interface ToastContextType {
  addToast: (toast: Omit<Toast, 'id'>) => void;
  removeToast: (id: string) => void;
  toasts: Toast[];
}

const ToastContext = React.createContext<ToastContextType | undefined>(undefined);

export function ToastProvider({ children }: ToastProviderProps) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = (toast: Omit<Toast, 'id'>) => {
    const id = Math.random().toString(36).substr(2, 9);
    const newToast = { ...toast, id };
    setToasts(prev => [...prev, newToast]);

    if (toast.duration !== 0) {
      setTimeout(() => {
        removeToast(id);
      }, toast.duration || 4000);
    }
  };

  const removeToast = (id: string) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  };

  return (
    <ToastContext.Provider value={{ addToast, removeToast, toasts }}>
      {children}
      <ToastContainer toasts={toasts} onRemove={removeToast} />
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = React.useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within ToastProvider');
  }
  return context;
}

function ToastContainer({ toasts, onRemove }: { toasts: Toast[]; onRemove: (id: string) => void }) {
  return (
    <div style={{
      position: 'fixed',
      top: '20px',
      right: '20px',
      zIndex: 1000,
      display: 'flex',
      flexDirection: 'column',
      gap: '12px',
      maxWidth: '400px'
    }}>
      {toasts.map(toast => (
        <ToastItem key={toast.id} toast={toast} onRemove={onRemove} />
      ))}
    </div>
  );
}

function ToastItem({ toast, onRemove }: { toast: Toast; onRemove: (id: string) => void }) {
  const getIcon = () => {
    switch (toast.type) {
      case 'success': return <CheckCircle size={20} style={{ color: '#10b981' }} />;
      case 'error': return <AlertTriangle size={20} style={{ color: '#ef4444' }} />;
      case 'warning': return <AlertTriangle size={20} style={{ color: '#f59e0b' }} />;
      case 'info': return <Info size={20} style={{ color: '#3b82f6' }} />;
    }
  };

  const getBorderColor = () => {
    switch (toast.type) {
      case 'success': return '#10b981';
      case 'error': return '#ef4444';
      case 'warning': return '#f59e0b';
      case 'info': return '#3b82f6';
    }
  };

  return (
    <div style={{
      background: 'rgba(15, 23, 42, 0.95)',
      backdropFilter: 'blur(10px)',
      border: `1px solid ${getBorderColor()}`,
      borderRadius: '8px',
      padding: '16px',
      boxShadow: '0 10px 25px rgba(0, 0, 0, 0.3)',
      animation: 'slideInRight 0.3s ease-out',
      minWidth: '300px'
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
        {getIcon()}
        <div style={{ flex: 1 }}>
          <h4 style={{ 
            color: '#ffffff', 
            fontSize: '14px', 
            fontWeight: '600', 
            margin: '0 0 4px 0' 
          }}>
            {toast.title}
          </h4>
          {toast.description && (
            <p style={{ 
              color: '#cbd5e1', 
              fontSize: '12px', 
              margin: 0,
              lineHeight: '1.4'
            }}>
              {toast.description}
            </p>
          )}
        </div>
        <button
          onClick={() => onRemove(toast.id)}
          style={{
            background: 'none',
            border: 'none',
            color: '#64748b',
            cursor: 'pointer',
            padding: '2px'
          }}
        >
          <X size={16} />
        </button>
      </div>
    </div>
  );
}