/*
   Typical pin layout used:
   -----------------------------------------------------------------------------------------
               MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
               Reader/PCD   Uno           Mega      Nano v3    Leonardo/Micro   Pro Micro
   Signal      Pin          Pin           Pin       Pin        Pin              Pin
   -----------------------------------------------------------------------------------------
   RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
   SPI SS      SDA(SS)      10            53        D10        10               10
   SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
   SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
   SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
*/

#define noVERBOSE

#include <SPI.h>
#include <MFRC522.h>

#include <MFRC522Hack.h>

#define RST_PIN   5
#define SS_PIN    53

MFRC522 mfrc522(SS_PIN, RST_PIN);

MFRC522::MIFARE_Key key;

void setup() {
  Serial.begin(115200);  // Initialize serial communications with the PC
  while (!Serial)
    ;

  SPI.begin();         // Init SPI bus
  mfrc522.PCD_Init();  // Init MFRC522 card
  Serial.println(F("RFID tool"));

  // Prepare key - default factory key
  //  key = { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };
  key = { {0x41, 0x4C, 0x41, 0x52, 0x4F, 0x4E} };

  //  key = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
}

void LogStatusCode( MFRC522::StatusCode code, const char *action = nullptr )
{
  if (!action)
    action = "";
  switch ( code )
  {
    case MFRC522::StatusCode::STATUS_OK:
      break;
    default:
      Serial.print( "ERR " );
      Serial.print( action );
      Serial.print( ":" );
      Serial.println( MFRC522::GetStatusCodeName( code ) );
  }
}

void dump_byte_array(byte *buffer, byte bufferSize)
{
  for (byte i = 0; i < bufferSize; i++)
  {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
  Serial.println();
}

#define SECTORS 16

//  ---------------------------------------------------------------------
//  Print card information
//  ---------------------------------------------------------------------

void print_card_info()
{
  Serial.println(F("---- BEGIN CARD INFO ----"));

  if ( ! mfrc522.PICC_IsNewCardPresent())
    return;
  if ( ! mfrc522.PICC_ReadCardSerial())
    return;

  Serial.print(F("Card UID:"));
  dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
  Serial.println(F("---- END CARD INFO ----"));
}

//  ---------------------------------------------------------------------
//  Read a sector (must be authenticated)
//  ---------------------------------------------------------------------

bool read_block( byte *dest, int sector, int block )
{
  static byte buffer[18];
  byte bufferSize = 18;
  MFRC522::StatusCode status = mfrc522.MIFARE_Read( sector * 4 + block, buffer, &bufferSize);
  if (status)
  {
    Serial.print( "bool ::read_block( byte *dest, " );
    Serial.print( sector );
    Serial.print( ", " );
    Serial.print( block );
    Serial.print( " ) => " );
    Serial.println( MFRC522::GetStatusCodeName( status ) );
    return false;
  }
  memcpy( dest, buffer, 16 );
  return true;
}

void print_hex1( byte b )
{
  if (b > 9)
    b = b - 10 + 'A' - '0';
  Serial.print( (char)('0' + b) );
}

void print_hex2( byte b )
{
  print_hex1( b >> 4 );
  print_hex1( b & 0xf );
}

void print_bytes(byte *p, int size )
{
  for (byte i = 0; i < size; i++)
  {
    if (i > 0)
      Serial.print( " " );
    print_hex2( p[i] );
  }
}

void color_bg_white();
void color_bg_reset();

void print_ascii( byte b )
{
  if (b<0x20 || b>=0x7f)
  {
///    color_bg_white();
    Serial.print( '.' );
///    color_reset();
  }
  else
    Serial.print( (char)b );
}

void print_ascii(byte *p, int size )
{
  for (byte i = 0; i < size; i++)
  {
    print_ascii( p[i] );
    if ((i%4)==3)
      Serial.print( " " );
  }
}

void print_key( byte *key )
{
  print_bytes( key, 6 );
}

void print_access_trailer( byte a )
{
  Serial.print( "KEYA W=" );
  switch (a)
  {
    case 0:
    case 4:
      Serial.print( "A" );
      break;
    case 2:
    case 5:
      Serial.print( "B" );
      break;
    default:
      Serial.print( "never" );    
      break;
  }

  Serial.print( " / COND R=" );
  switch (a)
  {
    case 0:
    case 1:
    case 4:
      Serial.print( "A" );
      break;
    default:
      Serial.print( "A|B" );
      break;
  }

  Serial.print( " W=" );
  switch (a)
  {
    case 4:
      Serial.print( "A" );
      break;
    case 5:
    case 6:
      Serial.print( "B" );
      break;
    default:
      Serial.print( "never" );
      break;
  }


  Serial.print( " / KEYB R=" );
  switch (a)
  {
    case 0:
    case 1:
    case 4:
      Serial.print( "A" );
      break;
    default:
      Serial.print( "never" );    
      break;
  }
  Serial.print( " W=" );
  switch (a)
  {
    case 0:
    case 4:
      Serial.print( "A" );
      break;
    case 2:
    case 5:
      Serial.print( "B" );
      break;
    default:
      Serial.print( "never" );    
      break;
  }
  
  //  Missing incr, decr
}

void print_access_data( byte a )
{
  Serial.print( "R=" );
  if (a<=4) Serial.print( "A|B" );
  else if (a<=6) Serial.print( "B" );
  else Serial.print( "NEVER" );

  Serial.print( " / W=" );
  switch (a)
  {
    case 0:
      Serial.print( "A|B" );
      break;
    case 1:
    case 4:
    case 6:
    case 7:
      Serial.print( "NEVER" );
      break;
    default:
      Serial.print( "B" );
      break;
  }

  //  Missing incr, decr
}

void color_fg_bright() { Serial.print( "\033[37;1m" ); }

void color_fg_black() { Serial.print( "\033[30m" ); }
void color_fg_red() { Serial.print( "\033[31m" ); }
void color_fg_green() { Serial.print( "\033[32m" ); }
void color_fg_yellow() { Serial.print( "\033[33m" ); }
void color_fg_blue() { Serial.print( "\033[34m" ); }
void color_fg_magenta() { Serial.print( "\033[35m" ); }
void color_fg_cyan() { Serial.print( "\033[36m" ); }
void color_fg_white() { Serial.print( "\033[37m" ); }

void color_bg_black() { Serial.print( "\033[40m" ); }
void color_bg_red() { Serial.print( "\033[41m" ); }
void color_bg_green() { Serial.print( "\033[42m" ); }
void color_bg_yellow() { Serial.print( "\033[43m" ); }
void color_bg_blue() { Serial.print( "\033[44m" ); }
void color_bg_magenta() { Serial.print( "\033[45m" ); }
void color_bg_cyan() { Serial.print( "\033[46m" ); }
void color_bg_white() { Serial.print( "\033[47m" ); }

void color_reset() { Serial.print( "\033[0m" ); }


bool authenticate( int sector, int key_ab, byte *key )
{
#ifdef VERBOSE
  Serial.print( "AUTH :" ); Serial.print( sector ); Serial.print( "/" ); print_key(key); Serial.println();
#endif
  
  MFRC522::StatusCode status;
  status = mfrc522.PCD_Authenticate( key_ab == 0 ? MFRC522::PICC_CMD_MF_AUTH_KEY_A : MFRC522::PICC_CMD_MF_AUTH_KEY_B, sector * 4, (MFRC522::MIFARE_Key*)key, &mfrc522.uid);
#ifdef VERBOSE
    Serial.print( "bool ::authenticate( " );
    Serial.print( sector );
    Serial.print( ", " );
    Serial.print( key_ab==0?"A":"B" );
    Serial.print( ", " );
    print_key( key );
    Serial.print( " ) => " );
    Serial.println( MFRC522::GetStatusCodeName( status ) );
#endif
  return !status;
}

bool connect()
{
  if ( ! mfrc522.PICC_IsNewCardPresent())
    return false;
  if ( ! mfrc522.PICC_ReadCardSerial())
    return false;
  return true;
}


#define KEY_A 0x01
#define KEY_B 0x02
#define DATA 0x04


class card
{
    bool connected;

    int status[SECTORS];
    byte data[SECTORS * 4 * 16];
    byte keys[SECTORS][2][6];

public:
byte *get_data( int sector, int block )
    {
      return data + sector * 16 * 4 + block * 16;
    }
private:

    byte block0_check_byte() { return get_data(0,0)[4]; }

    byte compute_block0_check_byte()
    {
      return get_data(0,0)[0] ^ get_data(0,0)[1] ^ get_data(0,0)[2] ^ get_data(0,0)[3];
    }
    
    bool block0_check_byte_ok() { return block0_check_byte()==compute_block0_check_byte(); }

  byte *c_x( int sector ) { return get_data( sector, 3 ) + 6; }

  // Return the nth nibble of access rights in sector trailer
  byte cx_nibble( int sector, int nibble )
  {
    byte b = c_x(sector)[nibble/2];
    if (nibble%2)
      b >>= 4;
    else
      b &= 0xf;
    return b;
  }

  // bit n of all accesses
  byte c1x( int sector ) { return cx_nibble( sector, 3 ); }
  byte c2x( int sector ) { return cx_nibble( sector, 4 ); }
  byte c3x( int sector ) { return cx_nibble( sector, 5 ); }
  // verification bit of all accesses
  byte c1x_alt( int sector ) { return cx_nibble( sector, 0 )^0xf; }
  byte c2x_alt( int sector ) { return cx_nibble( sector, 1 )^0xf; }
  byte c3x_alt( int sector ) { return cx_nibble( sector, 2 )^0xf; }

  byte access( int sector, int block )
  {
    byte res = 0;
    byte mask = 1<<block;
    if (c1x(sector)&mask) res |= 1;
    if (c2x(sector)&mask) res |= 2;
    if (c3x(sector)&mask) res |= 4;
    return res;
  }

  byte access_alt( int sector, int block )
  {
    byte res = 0;
    byte mask = 1<<block;
    if (c1x_alt(sector)&mask) res |= 4;
    if (c2x_alt(sector)&mask) res |= 2;
    if (c3x_alt(sector)&mask) res |= 1;
    return res;
  }

  int &get_status( int sector )
    {
      return status[sector];
    }


    
    void connect_if_needed()
    {
      if (connected)
        return;

///      Serial.println(F("---- BEGIN CARD INFO ----"));

      if (!connect())
        return;

      connected = true;

//      Serial.print(F("Card UID:"));
//      dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
//      Serial.print(F("PICC type: "));
//      MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
//      Serial.println(mfrc522.PICC_GetTypeName(piccType));
//      Serial.println(F("---- END CARD INFO ----"));
    }

    bool authenticate( int sector, int key_ab )
    {
      connect_if_needed();
      if (!::authenticate(sector,key_ab,get_key(sector,key_ab)))
      {
#ifdef VERBOSE
        Serial.println( "bool card::authenticate(sector,key_ab) failed" );
#endif
        connected = false;
        return false;
      }
      return true;
    }
    
    bool try_key( int sector, int key_ab, byte *key )
    {
#ifdef VERBOSE
      print_key( key );
#endif
      connect_if_needed();
      if (!::authenticate(sector,key_ab,key))
      {
#ifdef VERBOSE
        Serial.println( "bool card::try_key(sector,key_ab,key) => wrong key" );
#endif
        connected = false;
        return false;
      }
      Serial.print("*");
#ifdef VERBOSE
      print_key( key );
#endif
      memcpy( get_key( sector, key_ab ), key, 6 );
      get_status( sector ) |= (key_ab == 0 ? KEY_A : KEY_B);
      return true;
    }
    bool read_sector( int sector, int key_ab );

  public:
    card() : connected{ false }
    {
      reset();
    }

    void reset()
    {
      connected = false;
      for (int s = 0; s != SECTORS; s++)
        get_status(s) = 0;
    }

    void key_search();
    int key_scan();

    byte *get_key( int sector, int key_ab ) {
      return keys[sector][key_ab];
    }
    bool known_key( int sector, int key_ab ) {
      return !!(get_status( sector ) & (key_ab == 0 ? KEY_A : KEY_B));
    }

  bool read_sector( int sector );
  void print_sector( int sector );
  void print_all();

  void read_all()
  {
    for (int s=0;s!=SECTORS;s++)
      read_sector(s);
  }

  bool write_sector( int sector, byte *data );

  void test();
};

void card::key_search()
{
  Serial.print( "Searching for keys : " );
  auto count = key_scan();
  Serial.println();
  Serial.print( "Found " );
  Serial.print( count );
  Serial.println( "/32 keys" );
}

int card::key_scan()
{
  MFRC522::MIFARE_Key keys[] =  {
    //  #### BUG: unsyncs sometimes if first key is found

        {0x88, 0x29, 0xDA, 0x9D, 0xAF, 0x76},
        {0x41, 0x4C, 0x41, 0x52, 0x4F, 0x4E},
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        {0x42, 0x4C, 0x41, 0x52, 0x4F, 0x4E},
        {0x31, 0x4B, 0x49, 0x47, 0x49, 0x56},
        {0x48, 0x45, 0x58, 0x41, 0x43, 0x54},
        {0x4A, 0x63, 0x52, 0x68, 0x46, 0x77},
        {0x02, 0x12, 0x09, 0x19, 0x75, 0x91},
        {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
        {0x2E, 0xF7, 0x20, 0xF2, 0xAF, 0x76},
        {0xBF, 0x1F, 0x44, 0x24, 0xAF, 0x76},
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
        {0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0},
        {0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1},
        {0xA2, 0x2A, 0xE1, 0x29, 0xC0, 0x13},
        {0x49, 0xFA, 0xE4, 0xE3, 0x84, 0x9F},
        {0x38, 0xFC, 0xF3, 0x30, 0x72, 0xE0},
        {0x8A, 0xD5, 0x51, 0x7B, 0x4B, 0x18},
        {0x50, 0x93, 0x59, 0xF1, 0x31, 0xB1},
        {0x6C, 0x78, 0x92, 0x8E, 0x13, 0x17},
        {0xAA, 0x07, 0x20, 0x01, 0x87, 0x38},
        {0xA6, 0xCA, 0xC2, 0x88, 0x64, 0x12},
        {0x62, 0xD0, 0xC4, 0x24, 0xED, 0x8E},
        {0xE6, 0x4A, 0x98, 0x6A, 0x5D, 0x94},
        {0x8F, 0xA1, 0xD6, 0x01, 0xD0, 0xA2},
        {0x89, 0x34, 0x73, 0x50, 0xBD, 0x36},
        {0x66, 0xD2, 0xB7, 0xDC, 0x39, 0xEF},
        {0x6B, 0xC1, 0xE1, 0xAE, 0x54, 0x7D},
        {0x22, 0x72, 0x9A, 0x9B, 0xD4, 0x0F},

        {0x49, 0xfa, 0xe4, 0xe3, 0x84, 0x9f},
        {0x48, 0x45, 0x58, 0x41, 0x43, 0x54},
        {0xa2, 0x2a, 0xe1, 0x29, 0xc0, 0x13},
        {0x38, 0xfc, 0xf3, 0x30, 0x72, 0xe0},
        {0x8a, 0xd5, 0x51, 0x7b, 0x4b, 0x18},
        {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5},
        {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7},
        {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5},
        {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd},
        {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a},
        {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
        {0x71, 0x4c, 0x5c, 0x88, 0x6e, 0x97},
        {0x58, 0x7e, 0xe5, 0xf9, 0x35, 0x0f},
        {0xa0, 0x47, 0x8c, 0xc3, 0x90, 0x91},
        {0x53, 0x3c, 0xb6, 0xc7, 0x23, 0xf6},
        {0x8f, 0xd0, 0xa4, 0xf2, 0x56, 0xe9},
  };
#define KEY_COUNT (sizeof(keys) / sizeof(keys[0]))

  int total = 0;

static bool tested[SECTORS][2][KEY_COUNT];
  for (int i=0;i!=KEY_COUNT;i++)
    for (int s=0;s!=SECTORS;s++)
      for (int k=0;k!=2;k++)
        tested[s][k][i] = false;

  //  For each type type, we loop over each sector, trying to find the key
 for (int k = 0; k != 2; k++)
   for (int s = 0; s != SECTORS; s++)
    for (int i = 0; i != KEY_COUNT; i++)
        if (!tested[s][k][i] && !known_key(s, k))
        {
          tested[s][k][i] = true;
          if (try_key( s, k, (byte *) & (keys[i]) ))
          {
            //  If we found a key, we check if it is used in other sectors, as keys are often reused
            total++;
            if (total==SECTORS*2)
              return total;
            for (int k2 = 0; k2 != 2; k2++)
              for (int s2 = 0; s2 != SECTORS; s2++)
                if (!tested[s2][k2][i] && !known_key(s2, k2))
                {
                  tested[s2][k2][i] = true;
                  if (try_key( s2, k2, (byte *) & (keys[i]) ))
                  {
                    total++;
                    if (total==SECTORS*2)
                      return total;
                 }
                }
          }
        }
    return total;
}

bool card::read_sector( int sector, int key_ab )
{
  connect_if_needed();
  if (!authenticate(sector,key_ab))
  {
    connected = false;
    return false;
  }
 
  bool res = true;
  res &= read_block( get_data( sector, 0 ), sector, 0 );
  res &= read_block( get_data( sector, 1 ), sector, 1 );
  res &= read_block( get_data( sector, 2 ), sector, 2 );
  res &= read_block( get_data( sector, 3 ), sector, 3 );
  if (!res)
  {
    connected = false;
    return false;
  }
  if (get_status(sector)|KEY_A)
  {
    memcpy( get_data( sector,3 ), keys[sector][0], 6 );
  }
  
  get_status( sector ) |= DATA;
  return true;
}

bool card::read_sector( int sector )
{
  if (get_status( sector )&KEY_A)
  {
#ifdef VERBOSE
    Serial.print( "READ WITH KEY A" );
#endif
    return read_sector( sector, 0 );
  }
  //  ### DOES NOT WORK -- NEVER GOT KEY B TO SUCCEED IN READING
  if (get_status( sector )&KEY_B)
  {
#ifdef VERBOSE
    Serial.print( "READ WITH KEY B" );
#endif
    return read_sector( sector, 1 );
  }
  return false;
}

void card::print_sector( int sector )
{
  Serial.print( "SECTOR:" );
  print_hex2( sector );
  if (get_status( sector )&KEY_A)
  {
    Serial.print( " KEY A:" );
    //color_bg_green();
    color_fg_bright();
    print_key( get_key( sector, 0 ) );
    color_reset();
    Serial.print( " " );
  }
  if (get_status( sector )&KEY_B)
  {
    Serial.print( "  KEYB :" );
//    color_bg_yellow();
    color_fg_bright();
    print_key( get_key( sector, 1 ) );
    color_reset();
    Serial.print( "" );
  }
  
  if (!(get_status( sector )&DATA))
  {
    Serial.println( " SECTOR NOT READ" );
    return;
  }

  Serial.println();

 byte *buffer = get_data( sector, 0 );

    if (sector == 0)
    { //  Special case for manufacturer block
      Serial.print( "    " );
      Serial.print( "\033[31m" );
      Serial.print( "\033[47m" );
      print_bytes( buffer, 4 );
      color_reset();
      Serial.print( " " );

      if (block0_check_byte_ok())
      {
        color_bg_green();
        print_hex2( buffer[4] );
        color_reset();
      }
      else
      {
        color_bg_red();
        print_hex2( buffer[4] );
        color_reset();
      }
      
      Serial.print( "\033[0m" );
      Serial.print( "\033[31m" );
      Serial.print( " " );
      print_bytes( buffer+5, 11 );
      Serial.print( "\033[0m" );
      Serial.print( "  " );
      print_ascii( buffer, 16 );
      Serial.print( " read-only" );
    }

    else
    {
      Serial.print( "    " );
      print_bytes( buffer, 16 );
      Serial.print( "  " );
      print_ascii( buffer, 16 );
      Serial.print( " " );
      print_access_data( access( sector, 0 ) );
    }

    Serial.println();

    Serial.print( "    " );
    print_bytes( buffer + 16, 16 );
    Serial.print( "  " );
    print_ascii( buffer + 16, 16 );

    Serial.print( " " );
    print_access_data( access( sector, 1 ) );
    Serial.println();

    Serial.print( "    " );
    print_bytes( buffer + 32, 16 );
    Serial.print( "  " );
    print_ascii( buffer + 32, 16 );

    Serial.print( " " );
    print_access_data( access( sector, 2 ) );
    Serial.println();

    Serial.print( "    " );
    Serial.print( "\033[42m" );
    print_bytes( buffer + 48, 6 );
    Serial.print( "\033[0m" );

    Serial.print( " " );
    color_bg_cyan();
    print_bytes( buffer + 48 + 6, 3 );
    color_reset();
    Serial.print( " " );
    print_bytes( buffer + 48 + 6 + 3, 1 );
    Serial.print( " " );
    Serial.print( "\033[43m" );
    print_bytes( buffer + 48 + 6 + 4, 6 );
    Serial.print( "\033[0m" );
    Serial.print( "  " );
    print_ascii( buffer + 48, 16 );

    Serial.print( " " );
    print_access_trailer( access( sector, 3 ) );
    Serial.println();
    
    Serial.println();
}

void card::print_all()
{
  for (int sector=0;sector!=SECTORS;sector++)
    print_sector( sector );
}

//  Writes the in-memory sector to the card
//void card::write( int sector, int block )
//{
//  authenticate( sector, 0 );
//  MFRC522::StatusCode status = mfrc522.MIFARE_Write( sector*4+block, get_data( sector, block), 16 );
//  LogStatusCode( status, "MIFARE_Write" );
//}

//  #### SHOULD BE A SECTOR
bool card::write_sector( int sector, byte *data )
{
  //print_bytes( data, 64 );

  Serial.println( sector );
  
  authenticate( sector, 0 );
  MFRC522::StatusCode status;
  if (sector!=0)
  {
    status = mfrc522.MIFARE_Write( sector*4, data, 16 );
  LogStatusCode( status, "MIFARE_Write" );
  }
  status = mfrc522.MIFARE_Write( sector*4+1, data+16, 16 );
  LogStatusCode( status, "MIFARE_Write" );
  status = mfrc522.MIFARE_Write( sector*4+2, data+32, 16 );
  LogStatusCode( status, "MIFARE_Write" );
  status = mfrc522.MIFARE_Write( sector*4+3, data+48, 16 );
  LogStatusCode( status, "MIFARE_Write" );

  get_status( sector ) = 0;
}

void card::test()
{
//  strcpy( (char *)get_data( 3,1), "TEST 2" );
//  write( 3,1 );

  //  This just destroyed by rfid tag sectors 4 to 7 :-)
  //  static byte trailer[16] = { 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  //  status = mfrc522.PCD_Authenticate( MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &key, &mfrc522.uid);
  //  LogStatusCode( status, "PCD_Authenticate");
  //  status = mfrc522.MIFARE_Write( 7, trailer, 16 );
  //  LogStatusCode( status, "MIFARE_Write" );
}

//  ---------------------------------------------------------------------

int get_hex1()
{
  for (;;)
  {
    while (!Serial.available())
      ;
    char c = Serial.read();

    if (c >= 'a' && c <= 'f')
      c = c - 'a' + 'A';

    if (c < '0') continue;
    if (c > '9' && c < 'A') continue;
    if (c > 'F') continue;

    int n = c - '0';

    if (c >= 'A')
      n = c - 'A' + 10;

    if (n <= 16)
    {
      Serial.print( c );
      return n;
    }
  }
  /* NOT REACHED */
}

int get_hex2()
{
  int h = get_hex1();
  int l = get_hex1();
  return h * 16 + l;
}

MFRC522::MIFARE_Key get_key( const char *msg )
{
  Serial.print( msg );
  Serial.print( " : " );

  MFRC522::MIFARE_Key k;

  for (int i = 0; i != 6; i++)
  {
    k.keyByte[i] = get_hex2();
    Serial.print( " " );
  }

  return k;
}

//  ---------------------------------------------------------------------

int get_number()
{
  int n = 0;
  int c;
  bool has_num = false;

  do
  { while (!Serial.available())
      ;
    c = Serial.read();
    if (c >= '0' && c <= '9')
    {
      Serial.print( (char)c );
      n = n * 10 + c - '0';
      has_num = true;
    }
    if (has_num && c == 13)
      Serial.println();

  } while (!has_num || c != 13);

  return n;
}

int get_number( const char *msg, int min, int max )
{
  int number = 0;
  for (;;)
  {
    Serial.print( msg );
    Serial.print( " (between " );
    Serial.print( min );
    Serial.print( " and " );
    Serial.print( max );
    Serial.print( ") : " );

    number = get_number();
    if (number < min)
      Serial.println( "  Number too small" );
    else if (number > max)
      Serial.println( "  Number too large" );
    else
      return number;
  }
  /* NOT REACHED */
}

card source_card;
card destination_card;

void loop()
{

///  print_card_info();

    Serial.println( "1 - Read source card" );
    Serial.println( "2 - Read destination card" );
    Serial.println( "3 - Print source card" );
    Serial.println( "4 - Print destination card" );
    Serial.println( "9 - Scan for keys" );
    Serial.println( "0 - Exit" );
    print_card_info();

  for (;;)
  {

    //    for (int s = 0;s!=16;s++)
    //      print_sector( s, 0, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} );
    //      print_sector( s, 0, {0x41, 0x4C, 0x41, 0x52, 0x4F, 0x4E} );

    while (!Serial.available())
      ;
    auto c = Serial.read();
    switch (c)
    {
      case '1':
        source_card.reset();
        source_card.key_search();
        source_card.read_all();
        Serial.println();
        break;
      case '2':
        destination_card.reset();
        destination_card.key_search();
        destination_card.read_all();
        break;
      case '3':
        source_card.print_all();
        break;
      case '4':
        destination_card.print_all();
        break;
      case 'x':
        for (int sector=0;sector!=SECTORS;sector++)
          destination_card.write_sector(sector,source_card.get_data(sector,0));
      
//        source_card.test();
//          auto sector = get_number( "Sector", 0, SECTORS-1 );
///          auto key_ab = get_number( "Key (A=0,B=1)", 0, 1 );
///          auto key = get_key( "Key" );
//          source_card.print_sector( sector );
        break;
    }
  }
}


