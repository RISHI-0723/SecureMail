/**
 * Status badge component for displaying health status
 */
import React from 'react';

interface StatusBadgeProps {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown' | 'loading' | 'error';
  text?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, text }) => {
  const statusConfig = {
    healthy: {
      bg: 'bg-green-100',
      text: 'text-green-800',
      label: text || 'Healthy',
    },
    degraded: {
      bg: 'bg-yellow-100',
      text: 'text-yellow-800',
      label: text || 'Degraded',
    },
    unhealthy: {
      bg: 'bg-red-100',
      text: 'text-red-800',
      label: text || 'Unhealthy',
    },
    unknown: {
      bg: 'bg-gray-100',
      text: 'text-gray-800',
      label: text || 'Unknown',
    },
    loading: {
      bg: 'bg-blue-100',
      text: 'text-blue-800',
      label: text || 'Checking...',
    },
    error: {
      bg: 'bg-red-100',
      text: 'text-red-800',
      label: text || 'Error',
    },
  };

  const config = statusConfig[status];

  return (
    <span
      className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${config.bg} ${config.text}`}
    >
      {config.label}
    </span>
  );
};
