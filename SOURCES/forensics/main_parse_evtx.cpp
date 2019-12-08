/*
 * =====================================================================================
 *       Filename:  parse_evtx.cpp
 *    Description:  Parse EVTX format files
 *        Created:  09.01.2018 16:59:43
 *         Author:  Igor Kuznetsov (igosha)
 *         igosha@kaspersky.com
 *         2igosha@gmail.com
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <utils/win_types.h>
#include <unordered_map>
#include <vector>
#include <map>
#include <string>
#include "eventlist.h"

// #define PRINT_TAGS

#include <tools/wintime.h>

namespace {

#pragma pack(push, 1)

#define EVTX_HEADER_MAGIC	"ElfFile"

typedef struct
{
	char		magic[8];
	uint64_t	numberOfChunksAllocated;
	uint64_t	numberOfChunksUsed;
	uint64_t	checksum;
	uint32_t	flags;
	uint32_t	version;
	uint64_t	fileSize;
	uint8_t		reserved[0x1000 - 0x30];
}
EvtxHeader;

#define EVTX_CHUNK_HEADER_MAGIC	"ElfChnk"

typedef struct
{
	char		magic[8];
	uint64_t	firstRecordNumber;
	uint64_t	lastRecordNumber;
	uint64_t	firstRecordNumber2;
	uint64_t	lastRecordNumber2;
	uint32_t	chunkHeaderSize;
	uint8_t		reserved[0x80 - 0x2C];
	uint8_t		reserved2[0x200 - 0x80];
}
EvtxChunkHeader;

#define EVTX_CHUNK_SIZE		0x10000

typedef struct
{
	uint32_t	magic;
	uint32_t	size;
	uint64_t	number;
	uint64_t	timestamp;
}
EvtxRecordHeader;


typedef struct
{
	uint32_t	d1;
	uint16_t	w1;
	uint16_t	w2;
	uint8_t		b1[8];
}
EvtxGUID;
#pragma pack(pop)

typedef enum
{
	StateNormal		=	1,
	StateInAttribute	=	2,
}
XmlParseState;

struct TemplateDescription;

struct ParseContext {
	ParseContext*	chunkContext;
	const uint8_t*	data;
	size_t		dataLen;
	size_t		offset;
	size_t		offsetFromChunkStart;
	XmlParseState	state;
	TemplateDescription* currentTemplatePtr;
	char		cachedValue[256];

	bool	HaveEnoughData(size_t numBytes) const {
		return ( offset + numBytes <= dataLen );
	}

	void	SkipBytes(size_t numBytes) {
		offset += numBytes;
	}

	template<class c>
	bool	ReadData(c* result, size_t count = 1)
	{
		if ( !HaveEnoughData(sizeof(*result) * count) )
			return false;
		for (size_t idx = 0; idx < count; idx++)
		{
			result[idx] = *(c*)(data + offset);
			offset += sizeof(*result);
		}
		return true;
	}

	void InheritWithOffset(ParseContext* other, size_t wantedLen) {
		data = other->data + other->offset;
		dataLen = wantedLen;
		if ( other->offset + dataLen > other->dataLen ) {
			/*  invalid len specified, fix it */
			if ( other->offset >= other->dataLen ) {
				dataLen = 0; /* out of all bounds */
			} else {
				dataLen = other->dataLen - other->offset;
#if defined(PRINT_TAGS)
				printf("cap on wantedLen %08zX (%08zX), want %08zX, give %08zX\n", other->offset, other->offset, wantedLen, dataLen);
#endif
			}
		}
		offset = 0;
		chunkContext = other;
		offsetFromChunkStart = other->offset + other->offsetFromChunkStart;
		cachedValue[0] = 0;
	}

	void UpdateLen(size_t wantedLen){
		if ( wantedLen <= dataLen ) {
			dataLen = wantedLen;
		}
	}
};

bool	ParseBinXml(ParseContext* ctx, size_t chunkOffsetInFile);

struct TemplateArgPair {
	TemplateArgPair(const TemplateArgPair&) = delete;
	TemplateArgPair(TemplateArgPair&& other) {
		key = other.key;
		type = other.type;
		other.key = nullptr;
	}
	TemplateArgPair(const char* ekey, uint16_t etype){
		key = strdup(ekey);
		type = etype;
	}
	~TemplateArgPair() {
		if ( key ) {
			free(key);
		}
	}
	char*			key;
	uint16_t		type;
};

struct TemplateFixedPair {
	TemplateFixedPair(const TemplateFixedPair&) = delete;
	TemplateFixedPair(TemplateFixedPair&& other){
		key = other.key;
		value = other.value;
		other.key = nullptr;
		other.value = nullptr;
	}
	TemplateFixedPair(const char* ekey, const char* evalue) {
		key = strdup(ekey);
		value = strdup(evalue);
	}
	~TemplateFixedPair() {
		if ( key ) {
			free(key);
		}
		if ( value ) {
			free(value);
		}
	}
	char*			key;
	char*			value;
};

struct TemplateDescription {
	TemplateDescription() : shortID(0) {}
	uint32_t		shortID;
	std::vector<TemplateFixedPair>		fixed;
	std::unordered_map<uint16_t, TemplateArgPair>	args;

	void	RegisterFixedPair(const char* key, const char* value) {
		fixed.emplace_back(TemplateFixedPair(key, value));
	}

	void	RegisterArgPair(const char* key, uint16_t type, uint16_t argIdx) {
		args.emplace(std::make_pair(argIdx, TemplateArgPair(key ? key : "", type)));
	}

};

#define countof(arr) ( sizeof(arr) / sizeof(*arr) )

#define MAX_NAME_STACK_DEPTH	20
#define INVALID_STACK_DEPTH 	((ssize_t)-1)

struct NameStackElement{
	char	name[256];
};

// Current time 2 m 20 sec
constexpr unsigned maxNameStackDepth = 20;
class NameStack {
public:
	NameStack() : nameStack(maxNameStackDepth), nameStackPtr(INVALID_STACK_DEPTH) {}

	void Reset() {
		nameStackPtr = INVALID_STACK_DEPTH;
	}

	void	PushName(const char* name) {
		if ( nameStackPtr + 1 >= MAX_NAME_STACK_DEPTH )
			return;
		nameStackPtr++;
		strncpy(nameStack[nameStackPtr].name, name, sizeof(nameStack[nameStackPtr].name));
		nameStack[nameStackPtr].name[ sizeof(nameStack[nameStackPtr].name) - 1 ]  = 0;
	}

	void	PopName(void) {
		if ( nameStackPtr > INVALID_STACK_DEPTH )
			nameStackPtr--;
	}

	const char* GetName() const {
		if ( nameStackPtr <= INVALID_STACK_DEPTH || nameStackPtr >= MAX_NAME_STACK_DEPTH )
			return NULL;
		return nameStack[nameStackPtr].name;
	}

	const char* GetUpperName() const {
		if ( nameStackPtr <= INVALID_STACK_DEPTH || nameStackPtr >= MAX_NAME_STACK_DEPTH )
			return NULL;
		if ( nameStackPtr < 1 )
			return NULL;

		return nameStack[nameStackPtr - 1].name;
	}

private:
	std::vector<NameStackElement> nameStack;
	ssize_t		nameStackPtr;
};

NameStack nameStack;

class Templates {
public:
	// 2 m 29 sec with this map
	bool	IsKnownID(uint32_t	id, TemplateDescription** result) {
		auto it = knownIDs.find(id);
		if ( it == knownIDs.end() ) {
			return false;
		}
		*result = &it->second;
		return true;
	}

	bool	RegisterID(uint32_t	id, TemplateDescription** result) {
		knownIDs[id] = TemplateDescription{};
		auto it = knownIDs.find(id);
		if ( it == knownIDs.end() ) {
			return false;
		}
		*result = &it->second;
		return true;
	}

	void Reset() {
		knownIDs.clear();
	}

private:
	std::unordered_map<uint32_t,TemplateDescription>	knownIDs;
};

Templates ids;

std::unordered_map<uint16_t, std::string> eventDescriptionHashTable;
const char*	logonTypes[]	= { NULL, NULL, "Interactive", "Network", "Batch", "Service", NULL, "Unlock", "NetworkCleartext", "NewCredentials", "RemoteInteractive", "CachedInteractive"};

void	ResetTemplates(void)
{
	ids.Reset();
}

void	SetState(ParseContext* ctx, XmlParseState newState)
{
	if ( newState == ctx->state )
		return;

	if ( ctx->state == StateInAttribute )
		nameStack.PopName();

	ctx->state = newState;
}

void	UTF16ToUTF8(uint16_t w, char* buffer, size_t* bufferUsed, size_t bufferSize)
{
	uint32_t	charLength	=	1;
	uint8_t		msb		=	0;
	uint8_t		mask		=	0;

	if ( w > 0x7F )
	{
		charLength++;
		msb |= 0x80 + 0x40;
		mask = 0xFF;
	}
	if ( w > 0x7FF )
	{
		charLength++;
		msb |= 0x20;
		mask = 0x1F;
	}
	if ( w > 0xFFFF )
	{
		charLength++;
		msb |= 0x10;
		mask = 0x0F;
	}

	if ( *bufferUsed + charLength >= bufferSize )
		return;	/*  no buffer overruns */

	if ( charLength == 1 )
	{
		buffer[*bufferUsed] = w;
		(*bufferUsed)++;
		return;
	}

	// printf("\n%04X -> ", (uint16_t)w);

	for (uint32_t charIndex = charLength - 1; charIndex > 0; charIndex--)
	{
		buffer[*bufferUsed + charIndex] = 0x80 | ( w & 0x3F );
		// printf(" ... [%X] %02X ", charIndex, buffer[*bufferUsed + charIndex]);
		w >>= 6;
	}

	buffer[*bufferUsed] = msb | ( w & mask );

#if 0
	for (uint32_t idx = 0; idx < charLength; idx++)
		printf("%02X ", (uint8_t)buffer[*bufferUsed + idx]);
	printf("\n");
#endif

	*bufferUsed += charLength;
}

bool	ReadPrefixedUnicodeString(ParseContext* ctx, char* nameBuffer, size_t nameBufferSize, bool isNullTerminated)
{
	uint16_t	nameCharCnt;
	size_t		nameBufferUsed	=	0;
	size_t		idx		=	0;

	if ( !ctx->ReadData(&nameCharCnt) )
		return false;

	// TODO : convert UTF-16 to UTF-8
	for (idx = 0; idx < nameCharCnt && idx*2 < ( nameBufferSize - 1 ) ; idx ++)
	{
		uint16_t	w;

		if ( !ctx->ReadData(&w) )
			return false;
		UTF16ToUTF8(w, nameBuffer, &nameBufferUsed, nameBufferSize);
	}

	if ( nameBufferUsed >= nameBufferSize )
		nameBufferUsed = nameBufferSize - 1;
	nameBuffer[nameBufferUsed] = 0;

	ctx->SkipBytes((nameCharCnt - idx + ( isNullTerminated ? 1 : 0 ))*2);

	return true;
}

bool	ReadName(ParseContext* ctx, char* nameBuffer, size_t nameBufferSize)
{
	uint16_t	nameHash;
	uint32_t	chunkOffset;
	uint32_t	d;
	ParseContext	temporaryCtx(*ctx->chunkContext);
	ParseContext*	ctxPtr		=	ctx;

	if ( nameBufferSize < 2 )
		return false;
	nameBuffer[0] = 0;
	if ( !ctx->ReadData(&chunkOffset) )
		return false;
	if ( ctx->offset + ctx->offsetFromChunkStart != chunkOffset )
	{
		// printf("!!!!!! %08X %08X\n", chunkOffset, (uint32_t)(ctx->offset + ctx->offsetFromChunkStart));
		ctxPtr = &temporaryCtx;
		ctxPtr->offset = chunkOffset;
	}

	if ( !ctxPtr->ReadData(&d) )
		return false;
	if ( !ctxPtr->ReadData(&nameHash) )
		return false;
	if ( !ReadPrefixedUnicodeString(ctxPtr, nameBuffer, nameBufferSize, true) )
		return false;

	return true;
}

const char*	GetProperKeyName(ParseContext* ctx)
{
	const char*	key;
	const char*	upperName;

	key = nameStack.GetName();

	// printf("Key: %s Upper: %s\n", key, nameStack.GetUpperName());

	upperName = nameStack.GetUpperName();

	if ( ( upperName != NULL ) &&
		( key != nullptr ) &&
		!strcmp(key, "Data") &&
		!strcmp(upperName, "EventData") &&
		ctx->cachedValue[0] != 0 )
	{
		key = ctx->cachedValue;
	}

	return key;
}

bool	ParseValueText(ParseContext* ctx)
{
	uint8_t		stringType;
	char		valueBuffer[256];
	const char*	upperName;
	const char*	key;

	if ( !ctx->ReadData(&stringType) )
		return false;
	if ( !ReadPrefixedUnicodeString(ctx, valueBuffer, sizeof(valueBuffer), false) )
		return false;
	// printf("******* %s=%s", nameStack.GetName(), valueBuffer);

	key = GetProperKeyName(ctx);
	upperName = nameStack.GetUpperName();

	if ( ( key != NULL ) &&
		( ( upperName == NULL ) ||
		strcmp(key, "Name") ||
		strcmp(upperName, "Data") ) )
	{
		if ( ctx->currentTemplatePtr != nullptr ) {
			ctx->currentTemplatePtr->RegisterFixedPair(key, valueBuffer);
		}
	}

	SetState(ctx, StateNormal);

	strncpy(ctx->cachedValue, valueBuffer, sizeof(valueBuffer));
	ctx->cachedValue[sizeof(ctx->cachedValue)-1] = 0;

	return true;
}

bool	ParseAttributes(ParseContext* ctx)
{
	char		nameBuffer[256];

	if ( !ReadName(ctx, nameBuffer, sizeof(nameBuffer)) )
		return false;
	// printf(" %s", nameBuffer);

	nameStack.PushName(nameBuffer);
	SetState(ctx, StateInAttribute);

	return true;
}

bool	ParseOpenStartElement(ParseContext* ctx, bool hasAttributes)
{
	uint8_t		b;
	uint16_t	w;
	uint32_t	elementLength;
	uint32_t	attributeListLength	=	0;
	char		nameBuffer[256];

	if ( !ctx->ReadData(&w) )
		return false;
	if ( !ctx->ReadData(&elementLength) )
		return false;
	if ( !ReadName(ctx, nameBuffer, sizeof(nameBuffer)) )
		return false;
	if ( hasAttributes )
	{
		if ( !ctx->ReadData(&attributeListLength) )
			return false;
	}
#ifdef PRINT_TAGS
	printf("<%s [%08X] ", nameBuffer, attributeListLength);
	fflush(stdout);
#endif

	nameStack.PushName(nameBuffer);

	return true;
}

bool	ParseCloseStartElement(ParseContext* ctx)
{
	SetState(ctx, StateNormal);
#ifdef PRINT_TAGS
	printf(">");
	fflush(stdout);
#endif
	return true;
}

bool	ParseCloseElement(ParseContext* ctx)
{
	SetState(ctx, StateNormal);
	nameStack.PopName();

#ifdef PRINT_TAGS
	printf("</>");
	fflush(stdout);
#endif
	return true;
}

bool	ParseTemplateInstance(ParseContext* ctx)
{
	uint8_t		b;
	uint32_t	numArguments;
	uint32_t	shortID;
	uint32_t	tempResLen;
	uint32_t	totalArgLen		=	0;

	if ( !ctx->ReadData(&b) )
		return false;
	if ( b != 0x01 )
		return false;
	if ( !ctx->ReadData(&shortID) )
		return false;
	if ( !ctx->ReadData(&tempResLen) )
		return false;
	if ( !ctx->ReadData(&numArguments) )
		return false;

#if defined(PRINT_TAGS)
	printf("OK, template %08X, num arguments %X\n", shortID, numArguments);
#endif

	if ( !ids.IsKnownID(shortID, &ctx->currentTemplatePtr) )
	//if ( numArguments == 0x00000000 )
	{
		uint8_t		longID[16];
		uint32_t	templateBodyLen;
		ParseContext	templateCtx;

		/* template definition follows */
		if ( !ctx->ReadData(&longID[0], sizeof(longID)) )
			return false;
		if ( !ctx->ReadData(&templateBodyLen) )
			return false;
		// printf("Template body, len %08X\n", templateBodyLen);

		templateCtx.InheritWithOffset(ctx, templateBodyLen);  // this will also fix the body len if it's out of bounds

		if ( !ids.RegisterID(shortID, &templateCtx.currentTemplatePtr) ) {
			return false; // BAD
		}

		if ( !ParseBinXml(&templateCtx, 0) )
			return false;

		ctx->SkipBytes(templateBodyLen);

		if ( !ctx->ReadData(&numArguments) )
			return false;

		ctx->currentTemplatePtr = templateCtx.currentTemplatePtr;
	}

	// printf("Number of arguments: %08X\n", numArguments);

	for (auto &f : ctx->currentTemplatePtr->fixed){
		bool	alreadyPrinted	=	false;

		if ( !strcmp(f.key, "EventID") )
		{
			uint16_t	eventID	=	strtoul(f.value, NULL, 10);
			if ( ( eventID != 0 ) && ( eventDescriptionHashTable.find(eventID) != eventDescriptionHashTable.end() ) )
			{
				printf("'%s':%u (%s), ", f.key, eventID, eventDescriptionHashTable[eventID].c_str());
				alreadyPrinted = true;
			}
		}

		if ( !alreadyPrinted )
			printf("'%s':'%s', ", f.key, f.value);
	}

	// printf("\n");

	size_t		argumentMapCount	=	numArguments * 2;
	std::vector<uint16_t>	argumentMap(argumentMapCount);

	if ( !ctx->ReadData(&argumentMap[0], argumentMapCount) )
	{
		printf("Failed to read the arguments\n");
		return false;
	}

	for (uint64_t argumentIdx = 0; argumentIdx < numArguments; argumentIdx++)
	{
		uint16_t		argLen		=	argumentMap[argumentIdx*2];
		uint16_t		argType		=	argumentMap[argumentIdx*2 + 1];
		TemplateArgPair*	argPair		=	NULL;

		//printf("\n %08X : [%02X %02X %02X] Arg %" PRIX64" type %08X len %08X\n",
		//		(uint32_t)ctx->offset, ctx->data[ctx->offset], ctx->data[ctx->offset+1], ctx->data[ctx->offset+2],
		//		argumentIdx, argType, argLen);
		auto it = ctx->currentTemplatePtr->args.find(argumentIdx);
		if ( it != ctx->currentTemplatePtr->args.end() ) {
			argPair = &it->second;
		}

		if ( argPair == NULL )
		{
			// printf("Argument not found\n");
			ctx->SkipBytes(argLen);
		}
		else
		{
			uint8_t		v_b;
			uint16_t	v_w;
			uint32_t	v_d;
			uint64_t	v_q;
			time_t		unixTimestamp;
			struct tm	localtm;
			struct tm*	t;
			uint8_t		sid[2+6];
			EvtxGUID	guid;
			size_t		stringNumUsed	=	0;
			size_t		stringSize	=	0;

			switch(argType)
			{
			//// case 0x00:	/*  void */
				//break;
			case 0x01:	/*  String */ {
				stringSize = argLen*2+2;
				std::vector<char> stringBuffer(stringSize);
				for (size_t idx = 0; idx < argLen/2; idx++)
				{
					if ( !ctx->ReadData(&v_w) )
						return false;
					UTF16ToUTF8(v_w, &stringBuffer[0], &stringNumUsed, stringSize);
				}
				if ( stringNumUsed >= stringSize )
					stringNumUsed = stringSize - 1;
				stringBuffer[stringNumUsed] = 0;
				printf("'%s':'%s', ", argPair->key, &stringBuffer[0]);
				}
				break;
			case 0x04:	/*  uint8_t */
				if ( !ctx->ReadData(&v_b) )
					return false;
				printf("'%s':%02u, ", argPair->key, v_b);
				break;
			case 0x06:	/*  uint16_t */
				if ( !ctx->ReadData(&v_w) )
					return false;

				if ( !strcmp(argPair->key, "EventID") && ( eventDescriptionHashTable.find(v_w) != eventDescriptionHashTable.end()))
					printf("'%s':%04u (%s), ", argPair->key, v_w, eventDescriptionHashTable[v_w].c_str());
				else
					printf("'%s':%04u, ", argPair->key, v_w);
				break;
			case 0x08:	/*  uint32_t */
				if ( !ctx->ReadData(&v_d) )
					return false;

				if ( !strcmp(argPair->key, "LogonType") && ( v_d <= 11 ) && ( logonTypes[v_d] != NULL ))
					printf("'%s':%08u (%s), ", argPair->key, v_d, logonTypes[v_d]);
				else if ( !strcmp(argPair->key, "Address1") || !strcmp(argPair->key, "Address2") )
				{
					uint8_t*	ipPtr	=	reinterpret_cast<uint8_t*>(&v_d);
					printf("'%s':%08u (%u.%u.%u.%u), ", argPair->key, v_d, ipPtr[0], ipPtr[1], ipPtr[2], ipPtr[3]);
				}
				else
					printf("'%s':%08u, ", argPair->key, v_d);
				break;
			case 0x0A:	/*  uint64_t */
				if ( !ctx->ReadData(&v_q) )
					return false;
				printf("'%s':%016" PRIu64 ", ", argPair->key, v_q);
				break;
			case 0x0E:	/*  binary */
				printf("'%s':", argPair->key);
				for (size_t idx = 0; idx < argLen; idx++)
				{
					if ( !ctx->ReadData( &v_b) )
						return false;
					printf("%02X", v_b);
				}
				printf(", ");
				break;
			case 0x0F:	/* GUID */
				if ( !ctx->ReadData( &guid) )
					return false;
				printf("'%s':%08X-%02X-%02X-%02X%02X%02X%02X%02X%02X%02X%02X, ", argPair->key,
						guid.d1, guid.w1, guid.w2,
						guid.b1[0], guid.b1[1], guid.b1[2], guid.b1[3],
						guid.b1[4], guid.b1[5], guid.b1[6], guid.b1[7]);
				break;
			case 0x14:	/*  HexInt32 */
				if ( !ctx->ReadData(&v_d) )
					return false;
				printf("'%s':%08" PRIX32", ", argPair->key, v_d);
				break;

			case 0x15:	/*  HexInt64 */
				if ( !ctx->ReadData(&v_q) )
					return false;
				printf("'%s':%016" PRIX64 ", ", argPair->key, v_q);
				break;
			case 0x11:	/*  FileTime */
				if ( !ctx->ReadData( &v_q) )
					return false;
				unixTimestamp = UnixTimeFromFileTime(v_q);
				t = gmtime_r(&unixTimestamp, &localtm);
				if ( t == NULL )
					printf("'%s':%016" PRIX64 ", ", argPair->key, v_q);
				else
					printf("'%s':%04u.%02u.%02u-%02u:%02u:%02u, ",
							argPair->key,
							t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
				break;
			case 0x13:	/*  SID */
				if ( argLen < sizeof(sid) )
					return false;
				if ( !ctx->ReadData(sid, sizeof(sid)) )
					return false;
				v_q = 0;
				for (size_t idx = 0; idx < 6; idx++)
				{
					v_q <<= 8;
					v_q |= sid[2+idx];
				}
				printf("'%s':S-%u-%" PRIu64 "", argPair->key, sid[0], v_q);
				for (size_t idx = sizeof(sid); idx + 4 <= argLen; idx += 4)
				{
					if ( !ctx->ReadData( &v_d) )
						return false;
					printf("-%u", v_d);
				}
				printf(", ");
				break;
			case 0x21:	/*  BinXml */
				{
					ParseContext	temporaryCtx(*ctx);
					temporaryCtx.UpdateLen(temporaryCtx.offset + argLen);
					if ( !ParseBinXml(&temporaryCtx, 0) )
						;//return false;
					// printf("=====<<<<< %08X\n", argLen);
					ctx->SkipBytes(argLen);
				}
				break;
			case 0x81:	/*  StringArray */
				{
					/*  Null terminated unicode strings */
					ParseContext	temporaryCtx(*ctx);
					bool		inString		=	false;

					temporaryCtx.UpdateLen(temporaryCtx.offset + argLen);

					printf("'%s':[", argPair->key);

					while ( 1 )
					{
						char	utf8Buffer[8];
						size_t	utf8BufferUsed;

						if ( !temporaryCtx.ReadData( &v_w) )
							break;

						if ( v_w == '\r' || v_w == '\n' )
							v_w = ' ';

						if ( v_w == 0x0000 )
						{
							if ( inString )
							{
								printf("',");
								inString = false;
							}
						}
						else
						{
							utf8BufferUsed = 0;
							UTF16ToUTF8(v_w, utf8Buffer, &utf8BufferUsed, sizeof(utf8Buffer));
							utf8Buffer[utf8BufferUsed] = 0;
							printf("%s%s", inString ? "" : "'", utf8Buffer);
							inString = true;
						}
					}

					printf("%s], ", inString ? "'" : "");

					ctx->SkipBytes(argLen);
				}
				break;
			default:
				if ( argType != 0x00 )
					printf("'%s':'...//%04X[%04X]', ", argPair->key, argPair->type, argLen);
				ctx->SkipBytes(argLen);
				break;
			}
		}

		totalArgLen += argLen;
	}

	return true;
}


bool	ParseOptionalSubstitution(ParseContext* ctx)
{
	uint16_t	substitutionID;
	uint8_t		valueType;

	if ( !ctx->ReadData(&substitutionID) )
		return false;
	if ( !ctx->ReadData(&valueType) )
		return false;
	if ( valueType == 0x00 )
	{
		if ( !ctx->ReadData(&valueType) )
			return false;
	}

	// printf("******* %s=<<param %X/type %X>> ", nameStack.GetName(), substitutionID, valueType);
	if ( ctx->currentTemplatePtr != nullptr ) {
		ctx->currentTemplatePtr->RegisterArgPair(GetProperKeyName(ctx), valueType, substitutionID);
	}
	SetState(ctx, StateNormal);

	return true;
}

bool	ParseBinXmlPre(const uint8_t* data, size_t dataLen, size_t chunkOffsetInFile, size_t inChunkOffset)
{
	ParseContext	ctx;

	ctx.data = data;
	ctx.dataLen = dataLen;
	ctx.offset = inChunkOffset;
	ctx.currentTemplatePtr = nullptr;
	ctx.chunkContext = &ctx;
	ctx.offsetFromChunkStart = 0;
	ctx.cachedValue[0] = 0;

	return ParseBinXml(&ctx, chunkOffsetInFile);
}

bool	ParseBinXml(ParseContext* ctx, size_t chunkOffsetInFile) {
	bool	result	=	true;

	ctx->state = StateNormal;

#if defined(PRINT_TAGS)
	printf("ParseBinXml(%08X, %08X)\n", (uint32_t)ctx->offset, (uint32_t)ctx->dataLen);
#endif

	while ( result && ( ctx->offset < ctx->dataLen ) )
	{
		uint8_t	tag	=	ctx->data[ctx->offset++];

#if defined(PRINT_TAGS)
		size_t realOffset = chunkOffsetInFile + ctx->offset + ( ctx->data - ctx->chunkContext->data );

		printf("%08zX: %02X ", realOffset, tag);
		printf("%08zX: %02X %02X %02X", realOffset, tag, ctx->data[ctx->offset], ctx->data[ctx->offset+1]);
		fflush(stdout);
#endif

		switch(tag)
		{
		case 0x00:	/*  EOF */
			ctx->offset = ctx->dataLen;
			break;
		case 0x01:	/*  OpenStartElementToken */
			result = ParseOpenStartElement(ctx, false);
			break;
		case 0x41:
			result = ParseOpenStartElement(ctx, true);
			break;
		case 0x02:	/* CloseStartElementToken */
			result = ParseCloseStartElement(ctx);
			break;
		case 0x03:	/*  CloseEmptyElementToken */
		case 0x04:	/*  CloseElementToken */
			result = ParseCloseElement(ctx);
			break;
		case 0x05:	/*  ValueTextToken */
		case 0x45:
			result = ParseValueText(ctx);
			break;
		case 0x06:	/*  AttributeToken */
		case 0x46:
			result = ParseAttributes(ctx);
			break;
		case 0x07:	/* CDATASectionToken */
		case 0x47:
			break;
		case 0x08:	/* CharRefToken */
		case 0x48:
			break;
		case 0x09:	/*  EntityRefToken */
		case 0x49:
			break;
		case 0x0A:	/*  PITargetToken */
			break;
		case 0x0B:	/*  PIDataToken */
			break;
		case 0x0C: /*  TemplateInstanceToken */
			result = ParseTemplateInstance(ctx);
			break;
		case 0x0D:	/*  NormalSubstitutionToken */
		case 0x0E:	/*  OptionalSubstitutionToken */
			result = ParseOptionalSubstitution(ctx);
			break;
		case 0x0F: /*  FragmentHeaderToken */
			ctx->SkipBytes( 3);
			break;

		default:
			result = false;
			break;
		}

#if defined(PRINT_TAGS)
		printf("\n");
#endif
	}

	return result;
}

bool	ParseEVTXInt(int f) {
	EvtxHeader	header;
	uint64_t	off	=	0;
	std::vector<uint8_t> chunk(EVTX_CHUNK_SIZE);
	bool		result	=	true;

	if ( read(f, &header, sizeof(header)) != sizeof(header) )
		return false;
	if ( header.version != 0x00030001)
		return false;

#ifdef PRINT_TAGS
	printf("Number of chunks: %" PRIu64 " %" PRIu64 " header sz %zu\n", header.numberOfChunksAllocated, header.numberOfChunksUsed, sizeof(header));
#endif

	off = sizeof(header);

	while ( result )
	{
		EvtxChunkHeader*	chunkHeader	=	reinterpret_cast<EvtxChunkHeader*>(&chunk[0]);

		ResetTemplates();
		nameStack.Reset();

		if ( lseek(f, off, SEEK_SET) != off )
		{
			result = false;
			break;
		}
		if ( read(f, &chunk[0], chunk.size()) != chunk.size() )
			break;

		if ( memcmp(chunkHeader->magic, EVTX_CHUNK_HEADER_MAGIC, sizeof(EVTX_CHUNK_HEADER_MAGIC)) )
		{
			// result = false;
			break;
		}

		// printf("Chunk %" PRIu64 " .. %" PRIu64 "\n", chunkHeader->firstRecordNumber, chunkHeader->lastRecordNumber);

		uint64_t inRecordOff = sizeof(*chunkHeader);

		while ( result )
		{
			EvtxRecordHeader*	recordHeader	=	reinterpret_cast<EvtxRecordHeader*>(&chunk[inRecordOff]);
			time_t			unixTimestamp;
			struct tm		localtm;
			struct tm*		t;

			if ( inRecordOff + sizeof(*recordHeader) > chunk.size() )
				break;

			if ( recordHeader->magic != 0x00002a2a )
			{
#ifdef PRINT_TAGS
				printf("Record header mismatch at %08X\n", (uint32_t)(off + inRecordOff));
#endif
				break;
			}

			unixTimestamp = UnixTimeFromFileTime(recordHeader->timestamp);
			t = gmtime_r(&unixTimestamp, &localtm);
			if ( t == NULL )
			{
				result = false;
				break;
			}

			// printf("%" PRIX64 ": Record %" PRIu64 " %04u.%02u.%02u-%02u:%02u:%02u ", inRecordOff, recordHeader->number, t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
			printf("Record #%" PRIu64 " %04u-%02u-%02uT%02u:%02u:%02uZ ", recordHeader->number, t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

			if ( !ParseBinXmlPre(&chunk[0],
						chunk.size(),
						off,
						inRecordOff + sizeof(*recordHeader) ) )
			{
				if ( recordHeader->number >= chunkHeader->firstRecordNumber &&
						recordHeader->number <= chunkHeader->lastRecordNumber )
				{
					result = false;
				}
				break;
			}
			printf("\n");

			inRecordOff += recordHeader->size;
		}

		off += chunk.size();

		if ( inRecordOff > off )
		{
			result = false;
			break;
		}
	}

	return result;
}

bool	ParseEVTX(const char* fileName) {
	bool	result;
	int	f	=	open(fileName, O_RDONLY|O_BINARY);
	if ( f < 0 )
		return false;

	result = ParseEVTXInt(f);
	if ( !result )
		printf("Failed on %s\n", fileName);
	close(f);
	return result;
}

void InitEventDescriptions(void) {
	for (size_t idx = 0; idx < sizeof(eventDescriptions)/sizeof(eventDescriptions[0]); idx++)
	{
		char*		nptr	=	NULL;
		uint16_t	eventID	=	strtoul(eventDescriptions[idx], &nptr, 10);
		if ( ( nptr == NULL ) || ( eventID == 0 ) )
			continue;
		while (*nptr != ')' && *nptr != 0)
			nptr++;
		while (*nptr == ' ' || *nptr == ')')
			nptr++;
		// printf("%04u - %s\n", eventID, nptr);
		eventDescriptionHashTable[eventID] = nptr;
	}
}

#ifdef _WIN32

#if !defined(__MINGW64_VERSION_MAJOR) && !defined(_MSC_VER)

extern "C"
{
BOOL (WINAPI *Wow64DisableWow64FsRedirection)(
  PVOID *OldValue
)	= (BOOL(WINAPI*)(PVOID*))GetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "Wow64DisableWow64FsRedirection");

BOOL (WINAPI * Wow64RevertWow64FsRedirection)(
  PVOID OldValue )
	= (BOOL(WINAPI*)(PVOID))GetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "Wow64RevertWow64FsRedirection");
}

#endif

#endif

}

int main(int argc, char* argv[]) {
	void*	redir;

#ifdef _WIN32
	if (Wow64DisableWow64FsRedirection != NULL )
		Wow64DisableWow64FsRedirection(&redir);
#endif

	InitEventDescriptions();
	for (int idx = 1; idx < argc; idx++) {
		ParseEVTX(argv[idx]);
	}

#ifdef _WIN32
	if (Wow64RevertWow64FsRedirection != NULL)
		Wow64RevertWow64FsRedirection(redir);
#endif

	return 0;
}

