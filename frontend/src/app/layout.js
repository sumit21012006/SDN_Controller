import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' })

export const metadata = {
  title: 'SDN DDoS Protection Center',
  description: 'Real-time SDN-based DDoS Detection and Mitigation Dashboard powered by Ryu OpenFlow 1.3',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={inter.variable}>
      <body className="min-h-screen" style={{ background: 'var(--bg-primary)' }}>
        {children}
      </body>
    </html>
  )
}
