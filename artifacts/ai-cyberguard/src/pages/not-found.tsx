import { Card, CardContent } from '@/components/ui/card';
import { ArrowLeft, Radar } from 'lucide-react';
import { Link } from 'wouter';

export default function NotFound() {
  return (
    <div className="flex min-h-[65dvh] w-full items-center justify-center">
      <Card className="w-full max-w-md mx-4">
        <CardContent className="pt-6">
          <div className="mb-4 flex gap-3">
            <Radar className="h-8 w-8 text-primary" />
            <div><div className="cg-kicker">Signal lost</div><h1 className="mt-1 text-2xl font-extrabold tracking-[-.04em]">Page not found</h1></div>
          </div>
          <p className="mt-4 text-sm text-muted-foreground">That route is outside the monitored surface.</p>
          <Link href="/" data-testid="link-back-to-overview" className="cg-btn cg-btn-primary mt-5"><ArrowLeft size={14} />Back to overview</Link>
        </CardContent>
      </Card>
    </div>
  );
}
