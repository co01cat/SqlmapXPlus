exec master.dbo.sp_configure 'show advanced options',1;
RECONFIGURE WITH OVERRIDE;
exec master.dbo.sp_configure 'clr enabled',%ENABLE%;
RECONFIGURE WITH OVERRIDE;
EXEC master..sp_configure 'show advanced options',0;
RECONFIGURE WITH OVERRIDE;