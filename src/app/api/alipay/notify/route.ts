import { NextRequest } from 'next/server';
import { handlePaymentNotify } from '@/lib/order/service';
import { AlipayProvider } from '@/lib/alipay/provider';

const alipayProvider = new AlipayProvider();

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text();
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => {
      headers[key] = value;
    });

    const notification = await alipayProvider.verifyNotification(rawBody, headers);
    const success = await handlePaymentNotify(notification, alipayProvider.name);
    return new Response(success ? 'success' : 'fail', {
      headers: { 'Content-Type': 'text/plain' },
    });
  } catch (error) {
    console.error('Alipay notify error:', error);
    return new Response('fail', {
      headers: { 'Content-Type': 'text/plain' },
    });
  }
}
