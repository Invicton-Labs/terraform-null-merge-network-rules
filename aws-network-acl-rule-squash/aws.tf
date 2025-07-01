locals {
  protocol_encapsulations = [
    // -1 means all protocols
    {
      primary      = -1
      encapsulated = null
    }
  ]
  icmp_type_encapsulations = [
    // -1 means all ICMP types
    {
      primary      = -1
      encapsulated = null
    }
  ]
  icmp_code_encapsulations = [
    // -1 means all ICMP codes
    {
      primary      = -1
      encapsulated = null
    }
  ]
}
