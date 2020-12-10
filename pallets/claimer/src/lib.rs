#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::string_lit_as_bytes)]
//! BLX claimer
//! This pallet a stakeholder claiming an ApnToken via parcel number
//! It is a WIP

use core::{convert::TryInto, fmt};
use frame_support::{
	//codec::{Decode, Encode}, // used for on-chain storage
	decl_event, decl_module, decl_storage, debug, decl_error, // used for all of the different macros
	dispatch::{DispatchResult, DispatchError},// the returns from a dispatachable call which is a function that a user can call as part of an extrensic
	ensure, // used to verify things
	storage::{StorageDoubleMap, StorageMap, StorageValue}, // storage types used
	traits::{
		Get, // no idea
		ReservableCurrency, Currency, InstanceFilter, OriginTrait, IsType, 
		//IsSubType, //cant find this?
	},
	Parameter,
	dispatch::PostDispatchInfo,
	weights::{Weight, GetDispatchInfo},
};

use parity_scale_codec::{Decode, Encode};

// use sp_arithmetic;

use frame_system::{
	self as system, ensure_signed, ensure_none,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer, SubmitTransaction,
	},
};
use sp_runtime::{RuntimeDebug, traits::{Dispatchable, Zero, Hash, Member, Saturating}};
use sp_std::prelude::*; // imports a bunch of boiler plate

use sp_std::str; // string

use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	offchain as rt_offchain,
	offchain::storage::StorageValueRef,
	transaction_validity::{
		InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
		ValidTransaction,
	},
};

// We use `alt_serde`, and Xanewok-modified `serde_json` so that we can compile the program
//   with serde(features `std`) and alt_serde(features `no_std`).
use alt_serde::{Deserialize, Deserializer};

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");
pub const NUM_VEC_LEN: usize = 10;

// We are fetching information from github public API about organisation `substrate-developer-hub`.
// pub const HTTP_REMOTE_REQUEST_BYTES: &[u8] = b"https://spencerbh.github.io/sandbox/18102019manualstrip.json";
pub const HTTP_REMOTE_REQUEST_BYTES: &[u8] = b"http://164.90.155.116:8000/apn/chain/";
//pub const HTTP_HEADER_USER_AGENT: &[u8] = b"spencerbh";

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use crate::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
		MultiSignature, MultiSigner,
	};

	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	// implemented for ocw-runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

//pub use weights::WeightInfo;

type BalanceOf<T> = <<T as Trait>::Currency as Currency<<T as frame_system::Trait>::AccountId>>::Balance;


/////////////////////////////////////////////////////////////////////////////////// //////////////
 
 
/// This is the pallet's configuration trait
pub trait Trait: balances::Trait + system::Trait + CreateSignedTransaction<Call<Self>> {

	/// The currency mechanism.
	type Currency: ReservableCurrency<Self::AccountId>;

	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	
	/// The overarching dispatch call type.
	type Call: Parameter +  Dispatchable<Origin=Self::Origin, PostInfo=PostDispatchInfo> 
	+ GetDispatchInfo + From<Call<Self>> 
	//+ IsSubType<Call<Self>>
	+ IsType<<Self as frame_system::Trait>::Call>;
	
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

	/// A kind of proxy; specified with the proxy and passed in to the `IsProxyable` fitler.
	/// The instance filter determines whether a given call may be proxied under this type.
	///
	/// IMPORTANT: `Default` must be provided and MUST BE the the *most permissive* value.
	type ProxyType: Parameter + Member + Ord + PartialOrd + InstanceFilter<<Self as Trait>::Call>
		+ Default;

	/// The base amount of currency needed to reserve for creating a proxy.
	///
	/// This is held for an additional storage item whose value size is
	/// `sizeof(Balance)` bytes and whose key size is `sizeof(AccountId)` bytes.
	type ProxyDepositBase: Get<BalanceOf<Self>>;

	/// The amount of currency needed per proxy added.
	///
	/// This is held for adding 32 bytes plus an instance of `ProxyType` more into a pre-existing
	/// storage value.
	type ProxyDepositFactor: Get<BalanceOf<Self>>;

	/// The maximum amount of proxies allowed for a single account.
	type MaxProxies: Get<u16>;
	/// Weight information for extrinsics in this pallet.
	//type WeightInfo: WeightInfo;

	/// The maximum amount of time-delayed announcements that are allowed to be pending.
	type MaxPending: Get<u32>;

	/// The type of hash used for hashing the call.
	type CallHasher: Hash;

	/// The base amount of currency needed to reserve for creating an announcement.
	///
	/// This is held when a new storage item holding a `Balance` is created (typically 16 bytes).
	type AnnouncementDepositBase: Get<BalanceOf<Self>>;

	/// The amount of currency needed per announcement made.
	///
	/// This is held for adding an `AccountId`, `Hash` and `BlockNumber` (typically 68 bytes)
	/// into a pre-existing storage value.
	type AnnouncementDepositFactor: Get<BalanceOf<Self>>;
}

// Custom data type
#[derive(Debug)]
enum TransactionType {
	SignedSubmitNumber,
	UnsignedSubmitNumber,
	//HttpFetching,
	None,
}

/////////////////////////////////////////////////////////////////////////////////////////////////

pub type GroupIndex = u32; // this is Encode (which is necessary for double_map)

#[serde(crate = "alt_serde")]
#[derive(Deserialize, Encode, Decode, Default,Debug)]
pub struct ApnToken<
	//Hash, 
	//Balance
	> {
	super_apn: u32,
	agency_name: Vec<u8>,
	//area: u32,
	//balance: Balance,
	//annual_allocation: AnnualAllocation<Hash>, // needs to be converted to vector of structs or similar, review substrate kitties for more
}

/// The parameters under which a particular account has a proxy relationship with some other
/// account.
#[derive(Encode, Decode, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, RuntimeDebug)]
pub struct ProxyDefinition<AccountId, ProxyType, BlockNumber> {
	/// The account which may act on behalf of another.
	delegate: AccountId,
	/// A value defining the subset of calls that it is allowed to make.
	proxy_type: ProxyType,
	/// The number of blocks that an announcement must be in place for before the corresponding call
	/// may be dispatched. If zero, then no announcement is needed.
	delay: BlockNumber,
}

/// Details surrounding a specific instance of an announcement to make a call.
#[derive(Encode, Decode, Clone, Copy, Eq, PartialEq, RuntimeDebug)]
pub struct Announcement<AccountId, Hash, BlockNumber> {
	/// The account which made the announcement.
	real: AccountId,
	/// The hash of the call to be made.
	call_hash: Hash,
	/// The height at which the announcement was made.
	height: BlockNumber,
}

type CallHashOf<T> = <<T as Trait>::CallHasher as Hash>::Output;

 // TaskQueue, needs an extrinsic used to populate these fields
#[serde(crate = "alt_serde")]
#[derive(Deserialize, Encode, Decode, Default,Debug)]
pub struct TaskQueue {
	#[serde(deserialize_with = "de_string_to_bytes")]
	http_remote_reqst: Vec<u8>,
	#[serde(deserialize_with = "de_string_to_bytes")]
	http_header_usr: Vec<u8>,
}

 // TaskQueue, needs an extrinsic used to populate these fields
 #[serde(crate = "alt_serde")]
 #[derive(Deserialize, Encode, Decode, Default,Debug)]
 pub struct TaskQueueTwo {
	 apn: Vec<u8>,
 }

// Specifying serde path as `alt_serde`
// ref: https://serde.rs/container-attrs.html#crate
#[serde(crate = "alt_serde")]
#[derive(Deserialize, Encode, Decode, Default)]
struct GithubInfo {
	// Specify our own deserializing function to convert JSON string to vector of bytes
	apn: u32,
	#[serde(deserialize_with = "de_string_to_bytes")]
	agency_name: Vec<u8>,
}

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'de>,
{
	let s: &str = Deserialize::deserialize(de)?;
	Ok(s.as_bytes().to_vec())
}

impl fmt::Debug for GithubInfo {
	// `fmt` converts the vector of bytes inside the struct back to string for
	//   more friendly display.
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"{{ apn: {}, agencyname: {}, shape_area: not included, but we will want to potentially bring acres in to the picture }}",
			&self.apn,
			str::from_utf8(&self.agency_name).map_err(|_| fmt::Error)?,
			// &self.shape_area,
		)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

decl_storage! {
	trait Store for Module<T: Trait> as AccountClaimer {
		
		// Get Apn Tokens from account_id, super_apn
		pub ApnTokensBySuperApns get(fn super_things_by_super_apns):
			map hasher(blake2_128_concat) Vec<u8> => ApnToken;//<T::Balance>;			
		TaskQueueByNumber get(fn task_queue_by_number):
			map hasher(blake2_128_concat) u32 => TaskQueueTwo;
		// A bool to track if there is a task in the queue to be fetched via HTTP
		QueueAvailable get(fn queue_available): bool;

		TaskNumber get(fn task_number): Vec<u8>;

		/// The set of account proxies. Maps the account which has delegated to the accounts
		/// which are being delegated to, together with the amount held on deposit.
		pub Proxies get(fn proxies): map hasher(twox_64_concat) T::AccountId
			=> (Vec<ProxyDefinition<T::AccountId, T::ProxyType, T::BlockNumber>>, BalanceOf<T>);

		/// The announcements made by the proxy (key).
		pub Announcements get(fn announcements): map hasher(twox_64_concat) T::AccountId
			=> (Vec<Announcement<T::AccountId, CallHashOf<T>, T::BlockNumber>>, BalanceOf<T>);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

decl_event! (
	pub enum Event<T>
	where
		//<T as system::Trait>::Hash,
		//<T as balances::Trait>::Balance,
		AccountId = <T as system::Trait>::AccountId,
		ProxyType = <T as Trait>::ProxyType,
		Hash = CallHashOf<T>,
	{
		/// Event generated when a new number is accepted to contribute to the average.
		NewNumber(Option<AccountId>, u64),
		/// New member for `AllMembers` group
		NewMember(AccountId),
		/// New ApnToken claimed event includes super_apn
		NewApnTokenClaimed(u32),

		/// A proxy was executed correctly, with the given \[result\].
		ProxyExecuted(DispatchResult),
		/// Anonymous account has been created by new proxy with given
		/// disambiguation index and proxy type. \[anonymous, who, proxy_type, disambiguation_index\]
		AnonymousCreated(AccountId, AccountId, ProxyType, u16),
		/// An announcement was placed to make a call in the future. \[real, proxy, call_hash\]
		Announced(AccountId, AccountId, Hash),
	}
);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

decl_error! {
	pub enum Error for Module<T: Trait> {
		// Error returned when making signed transactions in off-chain worker
		SignedSubmitNumberError,
		// Error returned when making remote http fetching
		HttpFetchingError0,
		HttpFetchingError1,
		HttpFetchingError2,
		HttpFetchingError3,
		HttpFetchingError4,
		HttpFetchingError5,
		HttpFetchingError6,
		HttpFetchingError7,
		HttpFetchingError8,
		HttpFetchingError9,
		// Error returned when gh-info has already been fetched
		AlreadyFetched,
		/// There are too many proxies registered or too many announcements pending.
		TooMany,
		/// Proxy registration not found.
		NotFound,
		/// Sender is not a proxy of the account to be proxied.
		NotProxy,
		/// A call which is incompatible with the proxy type's filter was attempted.
		Unproxyable,
		/// Account is already a proxy.
		Duplicate,
		/// Call may not be made by proxy because it may escalate its privileges.
		NoPermission,
		/// Announcement, if made at all, was made too recently.
		Unannounced,
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		type Error = Error<T>;

		/// The base amount of currency needed to reserve for creating a proxy.
		const ProxyDepositBase: BalanceOf<T> = T::ProxyDepositBase::get();

		/// The amount of currency needed per proxy added.
		const ProxyDepositFactor: BalanceOf<T> = T::ProxyDepositFactor::get();

		/// The maximum amount of proxies allowed for a single account.
		const MaxProxies: u16 = T::MaxProxies::get();

		/// `MaxPending` metadata shadow.
		const MaxPending: u32 = T::MaxPending::get();

		/// `AnnouncementDepositBase` metadata shadow.
		const AnnouncementDepositBase: BalanceOf<T> = T::AnnouncementDepositBase::get();

		/// `AnnouncementDepositFactor` metadata shadow.
		const AnnouncementDepositFactor: BalanceOf<T> = T::AnnouncementDepositFactor::get();


		/// Dispatch the given `call` from an account that the sender is authorised for through
		/// `add_proxy`.
		///
		/// Removes any corresponding announcement(s).
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// Parameters:
		/// - `real`: The account that the proxy will make a call on behalf of.
		/// - `force_proxy_type`: Specify the exact proxy type to be used and checked for this call.
		/// - `call`: The call to be made by the `real` account.
		// #[weight = 0]
		// fn proxy(origin,
		// 	real: T::AccountId,
		// 	force_proxy_type: Option<T::ProxyType>,
		// 	call: Box<<T as Trait>::Call>,
		// ) {
		// 	let who = ensure_signed(origin)?;
		// 	let def = Self::find_proxy(&real, &who, force_proxy_type)?;
		// 	ensure!(def.delay.is_zero(), Error::<T>::Unannounced);

		// 	Self::do_proxy(def, real, *call);
		// }

		/// Register a proxy account for the sender that is able to make calls on its behalf.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// Parameters:
		/// - `proxy`: The account that the `caller` would like to make a proxy.
		/// - `proxy_type`: The permissions allowed for this proxy account.
		/// - `delay`: The announcement period required of the initial proxy. Will generally be
		/// zero.
		#[weight = 0]
		fn add_proxy(origin,
			delegate: T::AccountId,
			proxy_type: T::ProxyType,
			delay: T::BlockNumber,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::add_proxy_delegate(&who, delegate, proxy_type, delay)
		}

		/// Unregister a proxy account for the sender.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// Parameters:
		/// - `proxy`: The account that the `caller` would like to remove as a proxy.
		/// - `proxy_type`: The permissions currently enabled for the removed proxy account.
		// #[weight = 0]
		// fn remove_proxy(origin,
		// 	delegate: T::AccountId,
		// 	proxy_type: T::ProxyType,
		// 	delay: T::BlockNumber,
		// ) -> DispatchResult {
		// 	let who = ensure_signed(origin)?;
		// 	Self::remove_proxy_delegate(&who, delegate, proxy_type, delay)
		// }		


		/// Unregister all proxy accounts for the sender.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// WARNING: This may be called on accounts created by `anonymous`, however if done, then
		/// the unreserved fees will be inaccessible. **All access to this account will be lost.**
		// #[weight = 0]
		// fn remove_proxies(origin) {
		// 	let who = ensure_signed(origin)?;
		// 	let (_, old_deposit) = Proxies::<T>::take(&who);
		// 	T::Currency::unreserve(&who, old_deposit);
		// }		

		/// Spawn a fresh new account that is guaranteed to be otherwise inaccessible, and
		/// initialize it with a proxy of `proxy_type` for `origin` sender.
		///
		/// Requires a `Signed` origin.
		///
		/// - `proxy_type`: The type of the proxy that the sender will be registered as over the
		/// new account. This will almost always be the most permissive `ProxyType` possible to
		/// allow for maximum flexibility.
		/// - `index`: A disambiguation index, in case this is called multiple times in the same
		/// transaction (e.g. with `utility::batch`). Unless you're using `batch` you probably just
		/// want to use `0`.
		/// - `delay`: The announcement period required of the initial proxy. Will generally be
		/// zero.
		///
		/// Fails with `Duplicate` if this has already been called in this transaction, from the
		/// same sender, with the same parameters.
		///
		/// Fails if there are insufficient funds to pay for deposit.
		///
		/// TODO: Might be over counting 1 read
		#[weight = 0]
		pub fn anonymous(origin, proxy_type: T::ProxyType, delay: T::BlockNumber, index: u16) {
			let who = ensure_signed(origin)?;

			let anonymous = Self::anonymous_account(&who, &proxy_type, index, None);
			ensure!(!Proxies::<T>::contains_key(&anonymous), Error::<T>::Duplicate);
			let deposit = T::ProxyDepositBase::get() + T::ProxyDepositFactor::get();
			T::Currency::reserve(&who, deposit)?;
			let proxy_def = ProxyDefinition {
				delegate: who.clone(),
				proxy_type: proxy_type.clone(),
				delay,
			};
			Proxies::<T>::insert(&anonymous, (vec![proxy_def], deposit));
			Self::deposit_event(RawEvent::AnonymousCreated(anonymous, who, proxy_type, index));
		}


		/// Removes a previously spawned anonymous proxy.
		///
		/// WARNING: **All access to this account will be lost.** Any funds held in it will be
		/// inaccessible.
		///
		/// Requires a `Signed` origin, and the sender account must have been created by a call to
		/// `anonymous` with corresponding parameters.
		///
		/// - `spawner`: The account that originally called `anonymous` to create this account.
		/// - `index`: The disambiguation index originally passed to `anonymous`. Probably `0`.
		/// - `proxy_type`: The proxy type originally passed to `anonymous`.
		/// - `height`: The height of the chain when the call to `anonymous` was processed.
		/// - `ext_index`: The extrinsic index in which the call to `anonymous` was processed.
		///
		/// Fails with `NoPermission` in case the caller is not a previously created anonymous
		/// account whose `anonymous` call has corresponding parameters.
		///
		// #[weight = 0]
		// fn kill_anonymous(origin,
		// 	spawner: T::AccountId,
		// 	proxy_type: T::ProxyType,
		// 	index: u16,
		// 	#[compact] height: T::BlockNumber,
		// 	#[compact] ext_index: u32,
		// ) {
		// 	let who = ensure_signed(origin)?;

		// 	let when = (height, ext_index);
		// 	let proxy = Self::anonymous_account(&spawner, &proxy_type, index, Some(when));
		// 	ensure!(proxy == who, Error::<T>::NoPermission);

		// 	let (_, deposit) = Proxies::<T>::take(&who);
		// 	T::Currency::unreserve(&spawner, deposit);
		// }

		/// Publish the hash of a proxy-call that will be made in the future.
		///
		/// This must be called some number of blocks before the corresponding `proxy` is attempted
		/// if the delay associated with the proxy relationship is greater than zero.
		///
		/// No more than `MaxPending` announcements may be made at any one time.
		///
		/// This will take a deposit of `AnnouncementDepositFactor` as well as
		/// `AnnouncementDepositBase` if there are no other pending announcements.
		///
		/// The dispatch origin for this call must be _Signed_ and a proxy of `real`.
		///
		/// Parameters:
		/// - `real`: The account that the proxy will make a call on behalf of.
		/// - `call_hash`: The hash of the call to be made by the `real` account.
		///
		// #[weight = 0]
		// fn announce(origin, real: T::AccountId, call_hash: CallHashOf<T>) {
		// 	let who = ensure_signed(origin)?;
		// 	Proxies::<T>::get(&real).0.into_iter()
		// 		.find(|x| &x.delegate == &who)
		// 		.ok_or(Error::<T>::NotProxy)?;

		// 	let announcement = Announcement {
		// 		real: real.clone(),
		// 		call_hash: call_hash.clone(),
		// 		height: system::Module::<T>::block_number(),
		// 	};

		// 	Announcements::<T>::try_mutate(&who, |(ref mut pending, ref mut deposit)| {
		// 		ensure!(pending.len() < T::MaxPending::get() as usize, Error::<T>::TooMany);
		// 		pending.push(announcement);
		// 		Self::rejig_deposit(
		// 			&who,
		// 			*deposit,
		// 			T::AnnouncementDepositBase::get(),
		// 			T::AnnouncementDepositFactor::get(),
		// 			pending.len(),
		// 		).map(|d| d.expect("Just pushed; pending.len() > 0; rejig_deposit returns Some; qed"))
		// 		.map(|d| *deposit = d)
		// 	})?;
		// 	Self::deposit_event(RawEvent::Announced(real, who, call_hash));
		// }

		/// Remove a given announcement.
		///
		/// May be called by a proxy account to remove a call they previously announced and return
		/// the deposit.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// Parameters:
		/// - `real`: The account that the proxy will make a call on behalf of.
		/// - `call_hash`: The hash of the call to be made by the `real` account.
		///
		// #[weight = 0]
		// fn remove_announcement(origin, real: T::AccountId, call_hash: CallHashOf<T>) {
		// 	let who = ensure_signed(origin)?;
		// 	Self::edit_announcements(&who, |ann| ann.real != real || ann.call_hash != call_hash)?;
		// }

		/// Remove the given announcement of a delegate.
		///
		/// May be called by a target (proxied) account to remove a call that one of their delegates
		/// (`delegate`) has announced they want to execute. The deposit is returned.
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// Parameters:
		/// - `delegate`: The account that previously announced the call.
		/// - `call_hash`: The hash of the call to be made.
		// #[weight = 0]
		// fn reject_announcement(origin, delegate: T::AccountId, call_hash: CallHashOf<T>) {
		// 	let who = ensure_signed(origin)?;
		// 	Self::edit_announcements(&delegate, |ann| ann.real != who || ann.call_hash != call_hash)?;
		// }

		/// Dispatch the given `call` from an account that the sender is authorised for through
		/// `add_proxy`.
		///
		/// Removes any corresponding announcement(s).
		///
		/// The dispatch origin for this call must be _Signed_.
		///
		/// Parameters:
		/// - `real`: The account that the proxy will make a call on behalf of.
		/// - `force_proxy_type`: Specify the exact proxy type to be used and checked for this call.
		/// - `call`: The call to be made by the `real` account.
		#[weight = 0]
		pub fn proxy_announced(origin,
			delegate: T::AccountId,
			real: T::AccountId,
			force_proxy_type: Option<T::ProxyType>,
			call: Box<<T as Trait>::Call>,
		) {
			ensure_signed(origin)?;
			let def = Self::find_proxy(&real, &delegate, force_proxy_type)?;

			// let call_hash = T::CallHasher::hash_of(&call);
			// let now = system::Module::<T>::block_number();
			// Self::edit_announcements(&delegate, |ann|
			// 	ann.real != real || ann.call_hash != call_hash || now.saturating_sub(ann.height) < def.delay
			// ).map_err(|_| Error::<T>::Unannounced)?;

			Self::do_proxy(def, real, *call);
		}

		/// Adds a new task to the TaskQueue
		#[weight = 0]
		pub fn insert_new_task(origin, 
			apn: Vec<u8>) -> DispatchResult {
			let _ = ensure_signed(origin)?;
			let apn_duplicate = apn.clone();
			let task_queue = TaskQueueTwo {
				apn,
			};
			<TaskNumber>::put(apn_duplicate);
			QueueAvailable::put(true);
			Ok(())
		}

		/// Manually tell the chain there are no tasks in the task list, this is a hack, no bueno
		#[weight = 0]
		pub fn empty_tasks(origin) -> DispatchResult {
			QueueAvailable::put(false);
			Ok(())
		}

		// Create an ApnToken with given parameters
		//
		// @param super_apn apn used as ID
		// @param agency_name 
		// @param area of APN related to ApnToken

		#[weight = 0]
		pub fn submit_apn_signed(origin, super_apn: u32, agency_name: Vec<u8>, area: u32) -> DispatchResult {
			debug::info!("submit_apn_signed: {:?}", super_apn);
			let who = ensure_signed(origin)?;
			Self::update_apn(Some(who), super_apn, agency_name, area)
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			debug::info!("Entering off-chain workers");

			let result = 
				if Self::queue_available() == true {
					debug::info!("there is a task in the queue");
					debug::info!("the task status is {:?}", Self::queue_available());
					Self::fetch_if_needed(Self::task_number())
				} else {
					debug::info!("executing signed extrinsic");
					Self::signed_submit_apn()
			};
		}
	}
}


impl<T: Trait> Module<T> {

	/// Calculate the address of an anonymous account.
	///
	/// - `who`: The spawner account.
	/// - `proxy_type`: The type of the proxy that the sender will be registered as over the
	/// new account. This will almost always be the most permissive `ProxyType` possible to
	/// allow for maximum flexibility.
	/// - `index`: A disambiguation index, in case this is called multiple times in the same
	/// transaction (e.g. with `utility::batch`). Unless you're using `batch` you probably just
	/// want to use `0`.
	/// - `maybe_when`: The block height and extrinsic index of when the anonymous account was
	/// created. None to use current block height and extrinsic index.
	pub fn anonymous_account(
		who: &T::AccountId,
		proxy_type: &T::ProxyType,
		index: u16,
		maybe_when: Option<(T::BlockNumber, u32)>,
	) -> T::AccountId {
		let (height, ext_index) = maybe_when.unwrap_or_else(|| (
			system::Module::<T>::block_number(),
			system::Module::<T>::extrinsic_index().unwrap_or_default()
		));
		let entropy = (b"modlpy/proxy____", who, height, ext_index, proxy_type, index)
			.using_encoded(sp_io::hashing::blake2_256);
		T::AccountId::decode(&mut &entropy[..]).unwrap_or_default()
	}


	/// Register a proxy account for the delegator that is able to make calls on its behalf.
	///
	/// Parameters:
	/// - `delegator`: The delegator account.
	/// - `delegatee`: The account that the `delegator` would like to make a proxy.
	/// - `proxy_type`: The permissions allowed for this proxy account.
	/// - `delay`: The announcement period required of the initial proxy. Will generally be
	/// zero.
	pub fn add_proxy_delegate(
		delegator: &T::AccountId,
		delegatee: T::AccountId,
		proxy_type: T::ProxyType,
		delay: T::BlockNumber,
	) -> DispatchResult {
		Proxies::<T>::try_mutate(delegator, |(ref mut proxies, ref mut deposit)| {
			//ensure!(proxies.len() < T::MaxProxies::get() as usize, Error::<T>::TooMany);

			let proxy_def = ProxyDefinition { delegate: delegatee, proxy_type, delay };
			let i = proxies.binary_search(&proxy_def).err().ok_or(Error::<T>::Duplicate)?;
			proxies.insert(i, proxy_def);
			// let new_deposit = Self::deposit(proxies.len() as u32);
			// if new_deposit > *deposit {
			// 	T::Currency::reserve(delegator, new_deposit - *deposit)?;
			// } else if new_deposit < *deposit {
			// 	T::Currency::unreserve(delegator, *deposit - new_deposit);
			// }
			// *deposit = new_deposit;
			Ok(())
		})
	}



	fn update_apn(who: Option<T::AccountId>, super_apn: u32, agency_name: Vec<u8>, area: u32) -> DispatchResult {
		debug::info!("some info from offchain woah --->  apn {:?} | agency_name {:?} | area {:?} (not from offchain, hardcoded)", super_apn, agency_name, area);
		// Create new ApnToken
		let apn_token = ApnToken {
			super_apn,
			agency_name,
		};

		// Inserts the ApnToken on-chain, mapping  the super_apn
		<ApnTokensBySuperApns>::insert(Self::task_number(), apn_token);

		// Emits event
		Self::deposit_event(RawEvent::NewApnTokenClaimed(super_apn));
		Ok(())
	}

		/// Check if we have fetched github info before. If yes, we use the cached version that is
	///   stored in off-chain worker storage `storage`. If no, we fetch the remote info and then
	///   write the info into the storage for future retrieval.
	fn fetch_if_needed(apn: Vec<u8>) -> Result<(), Error<T>> {
		// Start off by creating a reference to Local Storage value.
		// Since the local storage is common for all offchain workers, it's a good practice
		// to prepend our entry with the pallet name.
		let s_info = StorageValueRef::persistent(b"offchain-demo::gh-info");
		let s_lock = StorageValueRef::persistent(b"offchain-demo::lock");

		// The local storage is persisted and shared between runs of the offchain workers,
		// and offchain workers may run concurrently. We can use the `mutate` function, to
		// write a storage entry in an atomic fashion.
		//
		// It has a similar API as `StorageValue` that offer `get`, `set`, `mutate`.
		// If we are using a get-check-set access pattern, we likely want to use `mutate` to access
		// the storage in one go.
		//
		// Ref: https://substrate.dev/rustdocs/v2.0.0-rc3/sp_runtime/offchain/storage/struct.StorageValueRef.html
		if let Some(Some(gh_info)) = s_info.get::<GithubInfo>() {
			// gh-info has already been fetched. Return early.
			debug::info!("cached gh-info 1: {:?}", gh_info);
			return Ok(());
		}

		// We are implementing a mutex lock here with `s_lock`
		let res: Result<Result<bool, bool>, Error<T>> = s_lock.mutate(|s: Option<Option<bool>>| {
			match s {
				// `s` can be one of the following:
				//   `None`: the lock has never been set. Treated as the lock is free
				//   `Some(None)`: unexpected case, treated it as AlreadyFetch
				//   `Some(Some(false))`: the lock is free
				//   `Some(Some(true))`: the lock is held

				// If the lock has never been set or is free (false), return true to execute `fetch_n_parse`
				None | Some(Some(false)) => Ok(true),

				// Otherwise, someone already hold the lock (true), we want to skip `fetch_n_parse`.
				// Covering cases: `Some(None)` and `Some(Some(true))`
				_ => Err(<Error<T>>::AlreadyFetched),
			}
		});

		// Cases of `res` returned result:
		//   `Err(<Error<T>>)` - lock is held, so we want to skip `fetch_n_parse` function.
		//   `Ok(Err(true))` - Another ocw is writing to the storage while we set it,
		//                     we also skip `fetch_n_parse` in this case.
		//   `Ok(Ok(true))` - successfully acquire the lock, so we run `fetch_n_parse`
		if let Ok(Ok(true)) = res {
			match Self::fetch_n_parse(apn) {
				Ok(gh_info) => {
					// set gh-info into the storage and release the lock
					s_info.set(&gh_info);
					s_lock.set(&false);

					debug::info!("fetched gh-info: {:?}", gh_info);
				}
				Err(err) => {
					// release the lock
					s_lock.set(&false);
					return Err(err);
				}
			}
		}
		Ok(())
	}

	/// Fetch from remote and deserialize the JSON to a struct
	fn fetch_n_parse(apn: Vec<u8>) -> Result<GithubInfo, Error<T>> {
		let resp_bytes = Self::fetch_from_remote(apn).map_err(|e| {
			debug::error!("fetch_from_remote error: {:?}", e);
			<Error<T>>::HttpFetchingError0
		})?;

		let resp_str = str::from_utf8(&resp_bytes).map_err(|_| <Error<T>>::HttpFetchingError1)?;
		// Print out our fetched JSON string
		debug::info!("{}", resp_str);

		// Deserializing JSON to struct, thanks to `serde` and `serde_derive`
		let gh_info: GithubInfo =
			serde_json::from_str(&resp_str).map_err(|_| <Error<T>>::HttpFetchingError2)?;
		Ok(gh_info)
	}

	/// This function uses the `offchain::http` API to query the remote github information,
	///   and returns the JSON response as vector of bytes.
	fn fetch_from_remote(apn: Vec<u8>) -> Result<Vec<u8>, Error<T>> {
		// enter github access info - will be replaced with actual database
		let mut remote_url_bytes = HTTP_REMOTE_REQUEST_BYTES.to_vec();

		let mut apn_duplicate = apn.clone();
				
		remote_url_bytes.append(&mut apn_duplicate);

		let remote_url =
			str::from_utf8(&remote_url_bytes).map_err(|_| <Error<T>>::HttpFetchingError4)?;

		debug::info!("sending request to: {}", remote_url);

		// Initiate an external HTTP GET request. This is using high-level wrappers from `sp_runtime`.
		let request = rt_offchain::http::Request::get(remote_url);

		// Keeping the offchain worker execution time reasonable, so limiting the call to be within 3s.
		let timeout = sp_io::offchain::timestamp().add(rt_offchain::Duration::from_millis(3000));

		// For github API request, we also need to specify `user-agent` in http request header.
		//   See: https://developer.github.com/v3/#user-agent-required
		let pending = request
		 	.deadline(timeout) // Setting the timeout time
		 	.send() // Sending the request out by the host
		 	.map_err(|_| <Error<T>>::HttpFetchingError6)?;

		// By default, the http request is async from the runtime perspective. So we are asking the
		//   runtime to wait here.
		// The returning value here is a `Result` of `Result`, so we are unwrapping it twice by two `?`
		//   ref: https://substrate.dev/rustdocs/v2.0.0-rc3/sp_runtime/offchain/http/struct.PendingRequest.html#method.try_wait
		let response = pending
			.try_wait(timeout)
			.map_err(|_| <Error<T>>::HttpFetchingError7)?
			.map_err(|_| <Error<T>>::HttpFetchingError8)?;

		if response.code != 200 {
			debug::error!("Unexpected http request status code: {}", response.code);
			return Err(<Error<T>>::HttpFetchingError9);
		}

		// Next we fully read the response body and collect it to a vector of bytes.
		Ok(response.body().collect::<Vec<u8>>())
	}

	fn signed_submit_apn() -> Result<(), Error<T>> {
		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			debug::error!("No local account available -- boi"); // HELP HERE
			return Err(<Error<T>>::SignedSubmitNumberError);
		}
		let s_info = StorageValueRef::persistent(b"offchain-demo::gh-info");
		debug::info!("we got to here 0.1");

		if let Some(Some(gh_info)) = s_info.get::<GithubInfo>() {
			debug::info!("we got to here 0.2");
			debug::info!("cached gh-info in submit function: {:?}", gh_info.apn);
			let s_a = gh_info.apn;
			let a_n = gh_info.agency_name;
			let a_a = 5555;

			let results = signer.send_signed_transaction(|_acct| {
				Call::submit_apn_signed(s_a, a_n.clone(), a_a)
			});
			for (acc, res) in &results {
				match res {
					Ok(()) => {
						debug::native::info!(
							"off-chain send_signed: acc: {:?}| apn: {:#?}",
							acc.id,
							s_a.clone()
						);
					}
					Err(e) => {
						//debug::error!("[{:?}] Failed in signed_submit_number: {:?}", acc.id, e);
						debug::error!("[{:?}] Failed in signed_submit_number", acc.id);
						return Err(<Error<T>>::SignedSubmitNumberError);
					}
				};
			}
		} else {
			debug::info!{"error 666"};
		};

		Ok(())
	}

	fn find_proxy(
		real: &T::AccountId,
		delegate: &T::AccountId,
		force_proxy_type: Option<T::ProxyType>,
	) -> Result<ProxyDefinition<T::AccountId, T::ProxyType, T::BlockNumber>, DispatchError> {
		let f = |x: &ProxyDefinition<T::AccountId, T::ProxyType, T::BlockNumber>| -> bool {
			&x.delegate == delegate && force_proxy_type.as_ref().map_or(true, |y| &x.proxy_type == y)
		};
		Ok(Proxies::<T>::get(real).0.into_iter().find(f).ok_or(Error::<T>::NotProxy)?)
	}

	pub fn do_proxy(
		def: ProxyDefinition<T::AccountId, T::ProxyType, T::BlockNumber>,
		real: T::AccountId,
		call: <T as Trait>::Call,
	) {
		// This is a freshly authenticated new account, the origin restrictions doesn't apply.
		let mut origin: T::Origin = system::RawOrigin::Signed(real).into();
		origin.add_filter(move |c: &<T as frame_system::Trait>::Call| {
			let c = <T as Trait>::Call::from_ref(c);
			// We make sure the proxy call does access this pallet to change modify proxies.
			// match c.is_sub_type() {
			// 	// Proxy call cannot add or remove a proxy with more permissions than it already has.
			// 	Some(Call::add_proxy(_, ref pt, _)) | Some(Call::remove_proxy(_, ref pt, _))
			// 		if !def.proxy_type.is_superset(&pt) => false,
			// 	// Proxy call cannot remove all proxies or kill anonymous proxies unless it has full permissions.
			// 	Some(Call::remove_proxies(..)) | Some(Call::kill_anonymous(..))
			// 		if def.proxy_type != T::ProxyType::default() => false,
			// 	_ => def.proxy_type.filter(c)
			// }
			def.proxy_type.filter(c)
		});
		let e = call.dispatch(origin);
		Self::deposit_event(RawEvent::ProxyExecuted(e.map(|_| ()).map_err(|e| e.error)));
	}
}