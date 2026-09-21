/**
 * Settings Page - User profile and application settings
 */
import { useState } from 'react';
import {
  User,
  Shield,
  Key,
  Bell,
  Monitor,
  Lock,
  CheckCircle,
  AlertCircle,
  Loader,
} from 'lucide-react';
import { api, ApiError } from '@/services/api';
import type { UserInfo } from '@/types';

interface SettingsPageProps {
  currentUser: UserInfo | null;
}

export function SettingsPage({ currentUser }: SettingsPageProps) {
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'notifications'>('profile');
  const [changingPassword, setChangingPassword] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSuccess, setPasswordSuccess] = useState(false);

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(false);

    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setPasswordError('New passwords do not match');
      return;
    }

    if (passwordForm.newPassword.length < 8) {
      setPasswordError('Password must be at least 8 characters');
      return;
    }

    setChangingPassword(true);
    try {
      await api.changePassword(
        passwordForm.currentPassword,
        passwordForm.newPassword
      );
      setPasswordSuccess(true);
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
    } catch (err) {
      if (err instanceof ApiError) {
        setPasswordError(err.message);
      } else {
        setPasswordError('Failed to change password');
      }
    } finally {
      setChangingPassword(false);
    }
  };

  const tabs = [
    { id: 'profile' as const, label: 'Profile', icon: <User className="w-4 h-4" /> },
    { id: 'security' as const, label: 'Security', icon: <Shield className="w-4 h-4" /> },
    { id: 'notifications' as const, label: 'Notifications', icon: <Bell className="w-4 h-4" /> },
  ];

  return (
    <div className="max-w-4xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-slate-400 mt-1">Manage your account and preferences</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-slate-800 pb-2">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`
              flex items-center gap-2 px-4 py-2 rounded-lg transition-colors
              ${activeTab === tab.id
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
              }
            `}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Profile Tab */}
      {activeTab === 'profile' && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <User className="w-5 h-5 text-cyan-400" />
            Profile Information
          </h3>

          {currentUser && (
            <div className="space-y-4">
              <div className="flex items-center gap-4 p-4 bg-slate-800/50 rounded-lg">
                <div className="w-16 h-16 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                  <User className="w-8 h-8 text-white" />
                </div>
                <div>
                  <p className="text-white font-medium text-lg">
                    {currentUser.full_name || currentUser.username}
                  </p>
                  <p className="text-slate-400">{currentUser.email}</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-slate-800/30 rounded-lg">
                  <label className="text-slate-400 text-sm">Username</label>
                  <p className="text-white font-medium mt-1">{currentUser.username}</p>
                </div>
                <div className="p-4 bg-slate-800/30 rounded-lg">
                  <label className="text-slate-400 text-sm">Email</label>
                  <p className="text-white font-medium mt-1">{currentUser.email}</p>
                </div>
                <div className="p-4 bg-slate-800/30 rounded-lg">
                  <label className="text-slate-400 text-sm">Role</label>
                  <p className="text-white font-medium mt-1 flex items-center gap-2">
                    <Shield className="w-4 h-4 text-cyan-400" />
                    {currentUser.role}
                  </p>
                </div>
                <div className="p-4 bg-slate-800/30 rounded-lg">
                  <label className="text-slate-400 text-sm">Account Status</label>
                  <p className="text-white font-medium mt-1 flex items-center gap-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full" />
                    Active
                  </p>
                </div>
              </div>

              {currentUser.last_login && (
                <div className="p-4 bg-slate-800/30 rounded-lg">
                  <label className="text-slate-400 text-sm">Last Login</label>
                  <p className="text-white font-medium mt-1">
                    {new Date(currentUser.last_login).toLocaleString()}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Security Tab */}
      {activeTab === 'security' && (
        <div className="space-y-6">
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Key className="w-5 h-5 text-cyan-400" />
              Change Password
            </h3>

            {passwordSuccess && (
              <div className="mb-4 p-3 bg-green-500/10 border border-green-500/30 rounded-lg flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <p className="text-green-300">Password changed successfully</p>
              </div>
            )}

            {passwordError && (
              <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-red-400" />
                <p className="text-red-300">{passwordError}</p>
              </div>
            )}

            <form onSubmit={handlePasswordChange} className="space-y-4">
              <div>
                <label className="block text-slate-400 text-sm mb-1">Current Password</label>
                <input
                  type="password"
                  value={passwordForm.currentPassword}
                  onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
                  className="w-full bg-slate-800 text-white border border-slate-700 rounded-lg px-4 py-2 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>
              <div>
                <label className="block text-slate-400 text-sm mb-1">New Password</label>
                <input
                  type="password"
                  value={passwordForm.newPassword}
                  onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
                  className="w-full bg-slate-800 text-white border border-slate-700 rounded-lg px-4 py-2 focus:outline-none focus:border-cyan-500"
                  required
                  minLength={8}
                />
              </div>
              <div>
                <label className="block text-slate-400 text-sm mb-1">Confirm New Password</label>
                <input
                  type="password"
                  value={passwordForm.confirmPassword}
                  onChange={(e) => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })}
                  className="w-full bg-slate-800 text-white border border-slate-700 rounded-lg px-4 py-2 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>
              <button
                type="submit"
                disabled={changingPassword}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {changingPassword ? (
                  <>
                    <Loader className="w-4 h-4 animate-spin" />
                    Changing...
                  </>
                ) : (
                  <>
                    <Key className="w-4 h-4" />
                    Change Password
                  </>
                )}
              </button>
            </form>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Lock className="w-5 h-5 text-cyan-400" />
              Session Security
            </h3>
            <div className="space-y-3 text-slate-400 text-sm">
              <p>Your session is secured with JWT authentication.</p>
              <p>Access tokens expire after 30 minutes of inactivity.</p>
              <p>All API requests are authenticated and logged.</p>
            </div>
          </div>
        </div>
      )}

      {/* Notifications Tab */}
      {activeTab === 'notifications' && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Bell className="w-5 h-5 text-cyan-400" />
            Notification Preferences
          </h3>
          <div className="text-center py-8">
            <Monitor className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400">Notification settings coming soon</p>
            <p className="text-slate-500 text-sm mt-1">
              Configure email and in-app notifications for analysis completion and security alerts.
            </p>
          </div>
        </div>
      )}

      {/* System Info */}
      <div className="mt-6 p-4 bg-slate-900/30 border border-slate-800/50 rounded-lg">
        <p className="text-slate-500 text-sm text-center">
          SecureMailScope v0.5.0 - AI-Assisted Cryptographic Security Posture Assessment
        </p>
      </div>
    </div>
  );
}
