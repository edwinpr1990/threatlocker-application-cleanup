"""Report-driven cleanup entry point for external scheduling; no schedule installed."""
import argparse,json,os,getpass,uuid
from pathlib import Path
from cleanup import Settings,Client,Run,parse_report

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--org',required=True);p.add_argument('--instance',default='d');p.add_argument('--user-instance',default='D')
    p.add_argument('--report',type=Path);p.add_argument('--fetch-report',action='store_true')
    p.add_argument('--application',action='append',default=[]);p.add_argument('--run-dir',type=Path,required=True)
    p.add_argument('--execute',action='store_true');p.add_argument('--confirm-count',type=int)
    p.add_argument('--resume',action='store_true');p.add_argument('--reconcile-only',action='store_true')
    args=p.parse_args();token=os.environ.get('TL_AUTHORIZATION') or getpass.getpass('Authorization: ')
    cfg=Settings(org=str(uuid.UUID(args.org)),token=token,instance=args.instance,user_instance=args.user_instance,mode='Bulk')
    cfg.validate();run=Run(cfg,args.run_dir)
    if not args.resume:
        rows=[]
        if args.fetch_report:
            c=Client(cfg)
            try:rows,_=parse_report(json.dumps(c.report()).encode(),'report.json',cfg.org)
            finally:c.close()
        elif args.report:rows,_=parse_report(args.report.read_bytes(),args.report.name,cfg.org)
        if not rows and not args.application:p.error('Supply a report or explicit application IDs.')
        run.prepare(rows,args.application)
    if args.execute or args.reconcile_only:
        if args.execute and args.confirm_count is None:p.error('--confirm-count is required for execution.')
        run.execute(args.confirm_count or 0,args.reconcile_only)
    print(json.dumps(run.audit()['counts'],indent=2))

if __name__=='__main__':main()
