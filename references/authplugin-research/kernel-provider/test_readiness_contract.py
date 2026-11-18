import pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parent
class ReadinessContract(unittest.TestCase):
 def test_selector_is_separate_from_provider_operations(self):
  source=(ROOT/'ElanNativeProbe.cpp').read_text();start=source.index('if (selector == ElanProbeReadiness)');end=source.index('if (nativeProviderIsSelector(selector))',start)
  block=source[start:end]
  for forbidden in ('providerACM(', 'getAvailability(', 'getPermissions(', 'providerOperation(', 'providerDispatch(', 'setAvailability(', 'mapRead(', 'mapWrite(', 'retireExact(', 'copyout('):self.assertNotIn(forbidden,block)
  self.assertIn('IOLockLock(providerLock)',block);self.assertIn('if (!report.gateBusy)',block)
  self.assertIn('sizeof(NativeReadinessReport)',block)
 def test_stage_failure_diagnostics(self):
  source=(ROOT/'ElanNativeProbe.cpp').read_text()
  for value in range(1,7):self.assertIn(f'&readinessFailure, {value}U',source)
  for key in ('NativeReadinessStage','NativeReadinessFailure','NativeRetirementReady','NativePlatformReady','NativeProviderReady'):self.assertIn('"'+key+'"',source)
 def test_catalog_business_result_is_not_io_error(self):
  source=(ROOT/'ElanNativeProbe.cpp').read_text();start=source.index('if (selector == ElanProviderCatalogBegin || selector == ElanProviderCatalogReplace)',source.index('IOReturn ELANNativeProbe::providerGated'))
  end=source.index('if (selector == ElanProviderAuthorizeEnrollment)',start);block=source[start:end]
  self.assertEqual(re.findall(r'return\s+(\w+)\s*;',block),['kIOReturnSuccess'])
 def test_readiness_client_never_falls_back_to_status(self):
  source=(ROOT/'probe-client.cpp').read_text();start=source.index('if (readiness) {');end=source.index('if (study) {',start);block=source[start:end]
  self.assertIn('ElanProbeReadiness',block);self.assertNotIn('ElanProbeStatus',block);self.assertIn('return status',block)
if __name__=='__main__':unittest.main()
